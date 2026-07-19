package limiter

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/juju/ratelimit"
	log "github.com/sirupsen/logrus"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	Nodetype      string
	SpeedLimit    int
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Key: Ip, value: Uid
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID, value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *ratelimit.Bucket
	AliveList     map[int]int    // Key: Uid, value: alive_ip
	mapsMu        sync.RWMutex   // Protects UUIDtoUID and AliveList
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func AddLimiter(nodetype string, tag string, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		Nodetype:      nodetype,
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     aliveList,
		OldUserOnline: new(sync.Map),
	}
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	l.mapsMu.Lock()
	defer l.mapsMu.Unlock()
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.UserOnlineIP.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.SpeedLimiter.Delete(format.UserTag(tag, deleted[i].Uuid))
		delete(l.UUIDtoUID, deleted[i].Uuid)
		delete(l.AliveList, deleted[i].Id)
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
	}
}


func (l *Limiter) SetAliveList(aliveList map[int]int) {
	l.mapsMu.Lock()
	l.AliveList = aliveList
	l.mapsMu.Unlock()
}

func (l *Limiter) aliveCount(uid int) int {
	l.mapsMu.RLock()
	defer l.mapsMu.RUnlock()
	return l.AliveList[uid]
}

// isConnectivityCheck determines if the request is a connectivity/captive portal check
func isConnectivityCheck(host string) bool {
	connectivityDomains := []string{
		"gstatic.com",
		"google.com",
		"captive.apple.com",
		"apple.com",
		"appleiphonecell.com",
		"clients3.google.com",
		"clients4.google.com",
		"connectivitycheck.android.com",
		"connectivitycheck.gstatic.com",
		"android.clients.google.com",
		"msftconnecttest.com",
		"msftncsi.com",
		"microsoft.com",
		"detectportal.firefox.com",
		"nmcheck.gnome.org",
		"spectrum.s3.amazonaws.com",
		"cloudflareportal.com",
		"cloudflarecp.com",
		"connectivity.cloudflareclient.com",
		"cp.cloudflare.com",
		"ibook.info",
		"itools.info",
		"thinkdifferent.us",
		"airport.us",
		"attwifi.apple.com",
	}

	host = strings.ToLower(host)
	for _, domain := range connectivityDomains {
		if strings.Contains(host, domain) {
			return true
		}
	}
	return false
}

func (l *Limiter) CheckLimit(taguuid string, ip string, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	return l.CheckLimitWithDestination(taguuid, ip, "", noSSUDP)
}

func (l *Limiter) CheckLimitWithDestination(taguuid string, ip string, destination string, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")

	// Skip device limiting for connectivity checks
	skipDeviceLimit := isConnectivityCheck(destination)
	if skipDeviceLimit {
		log.WithFields(log.Fields{
			"destination": destination,
			"ip":          ip,
		}).Debug("Skipping device limit for connectivity check")
	}

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			if u.SpeedLimit != 0 {
				userLimit = u.SpeedLimit
				u.DynamicSpeedLimit = 0
				u.ExpireTime = 0
			} else {
				l.UserLimitInfo.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
		}
	} else {
		return nil, true
	}
	if (noSSUDP || l.Nodetype == "hysteria2") && !skipDeviceLimit {
		// Store online user for device limit
		ipMap := new(sync.Map)
		ipMap.Store(ip, uid)
		aliveIp := l.aliveCount(uid)

		log.WithFields(log.Fields{
			"uid":         uid,
			"deviceLimit": deviceLimit,
			"aliveIp":     aliveIp,
			"ip":          ip,
			"taguuid":     taguuid,
		}).Info("CheckLimit Debug")

		// If any device is online
		if v, ok := l.UserOnlineIP.LoadOrStore(taguuid, ipMap); ok {
			ipMap := v.(*sync.Map)
			// If this is a new ip
			if _, ok := ipMap.LoadOrStore(ip, uid); !ok {
				if deviceLimit > 0 {
					if deviceLimit <= aliveIp {
						log.WithFields(log.Fields{
							"uid": uid,
							"ip":  ip,
						}).Info("CheckLimit Reject: deviceLimit <= aliveIp")
						ipMap.Delete(ip)
						return nil, true
					}
				}
			}
		} else if v, ok := l.OldUserOnline.Load(ip); ok {
			if v.(int) == uid {
				l.OldUserOnline.Delete(ip)
			}
		} else {
			if deviceLimit > 0 {
				if deviceLimit <= aliveIp {
					log.WithFields(log.Fields{
						"uid": uid,
						"ip":  ip,
					}).Info("CheckLimit Reject (New User): deviceLimit <= aliveIp")
					l.UserOnlineIP.Delete(taguuid)
					return nil, true
				}
			}
		}
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8 // If you need the Speed limit
	if limit > 0 {
		Bucket = ratelimit.NewBucketWithQuantum(time.Second, limit, limit) // Byte/s
		if v, ok := l.SpeedLimiter.LoadOrStore(taguuid, Bucket); ok {
			return v.(*ratelimit.Bucket), false
		} else {
			l.SpeedLimiter.Store(taguuid, Bucket)
			return Bucket, false
		}
	} else {
		return nil, false
	}
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	var onlineUser []panel.OnlineUser
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.OldUserOnline.Store(ip, uid)
			onlineUser = append(onlineUser, panel.OnlineUser{UID: uid, IP: ip})
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

// GetOnlineDevicesForTags aggregates online users across all limiters matching the provided tags, draining each limiter's UserOnlineIP map.
func GetOnlineDevicesForTags(tags []string) ([]panel.OnlineUser, error) {
	var onlineUsers []panel.OnlineUser
	limitLock.RLock()
	defer limitLock.RUnlock()

	for _, tag := range tags {
		l, ok := limiter[tag]
		if !ok {
			continue
		}
		l.UserOnlineIP.Range(func(key, value interface{}) bool {
			taguuid := key.(string)
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				uid := value.(int)
				ip := key.(string)
				l.OldUserOnline.Store(ip, uid)
				onlineUsers = append(onlineUsers, panel.OnlineUser{UID: uid, IP: ip})
				return true
			})
			l.UserOnlineIP.Delete(taguuid) // Reset online device
			return true
		})
	}

	return onlineUsers, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
