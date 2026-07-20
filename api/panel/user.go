package panel

import (
	"fmt"
	"path"

	"encoding/json"
)

type OnlineUser struct {
	UID int    `json:"uid"`
	IP  string `json:"ip"`
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
	ServiceId   string `json:"service_id,omitempty"` // Generic field for service-specific identity (e.g. WireGuard Key)
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

type UserOnlineBody struct {
	Users []OnlineUser `json:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

func (c *ClientV1) GetUserList(protocolName string) ([]UserInfo, error) {
	c.userMu.Lock()
	defer c.userMu.Unlock()

	const p = "/v1/server/user"
	etag := c.userEtags[protocolName]
	r, err := c.Client.R().
		SetQueryParam("protocol", protocolName).
		SetHeader("If-None-Match", etag).
		SetHeader("Cache-Control", "no-cache, no-store").
		SetHeader("Pragma", "no-cache").
		ForceContentType("application/json").
		SetDoNotParseResponse(true).
		Get(p)
	if err != nil {
		return nil, fmt.Errorf("failed to access %s: %w", path.Join(c.APIHost+p), err)
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("server response is empty")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		if cached, ok := c.userLists[protocolName]; ok && cached != nil {
			return cached.Users, nil
		}
		return []UserInfo{}, nil
	}

	if r.StatusCode() >= 400 {
		body := r.Body()
		return nil, fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), string(body))
	}

	userlist := &UserListBody{}
	if err := json.NewDecoder(r.RawResponse.Body).Decode(userlist); err != nil {
		return nil, fmt.Errorf("failed to decode user list: %w", err)
	}

	c.userEtags[protocolName] = r.Header().Get("ETag")
	c.userLists[protocolName] = userlist
	return userlist.Users, nil
}

type AliveResponse struct {
	Code int       `json:"code"`
	Msg  string    `json:"msg"`
	Data *AliveMap `json:"data"`
}

func (c *ClientV1) GetUserAlive() (map[int]int, error) {
	const path = "/v1/server/alivelist"
	r, err := c.Client.R().
		SetHeader("Cache-Control", "no-cache, no-store").
		SetHeader("Pragma", "no-cache").
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get alive list: %w", err)
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("failed to get alive list: received nil response or raw response")
	}
	if r.StatusCode() >= 399 {
		body := r.Body()
		return nil, fmt.Errorf("failed to get alive list: status %d, body: %s", r.StatusCode(), string(body))
	}
	defer r.RawResponse.Body.Close()

	aliveMap := &AliveMap{}
	if err := json.Unmarshal(r.Body(), aliveMap); err != nil {
		return nil, fmt.Errorf("failed to decode alive list: %w", err)
	}

	if aliveMap.Alive == nil {
		return nil, fmt.Errorf("alive field is missing in response")
	}

	return aliveMap.Alive, nil
}

type ServerPushUserTrafficRequest struct {
	Traffic []UserTraffic `json:"traffic"`
}

type UserTraffic struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (c *ClientV1) ReportUserTraffic(protocolName string, userTraffic *[]UserTraffic) error {
	traffic := make([]UserTraffic, 0)
	for _, t := range *userTraffic {
		traffic = append(traffic, UserTraffic{
			UID:      t.UID,
			Upload:   t.Upload,
			Download: t.Download,
		})
	}
	p := "/v1/server/push"
	req := ServerPushUserTrafficRequest{
		Traffic: traffic,
	}
	r, err := c.Client.R().
		SetQueryParam("protocol", protocolName).
		SetBody(req).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), string(body))
	}

	return nil
}

func (c *ClientV1) ReportNodeOnlineUsers(protocolName string, data *[]OnlineUser) error {
	const p = "/v1/server/online"
	users := UserOnlineBody{
		Users: *data,
	}
	r, err := c.Client.R().
		SetQueryParam("protocol", protocolName).
		SetBody(users).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), string(body))
	}

	return nil
}

// OutboundTraffic represents per-outbound traffic stats
type OutboundTraffic struct {
	Tag      string `json:"tag"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

type PushOutboundTrafficRequest struct {
	Traffic []OutboundTraffic `json:"traffic"`
}

func (c *ClientV1) PushOutboundTraffic(traffic []OutboundTraffic) error {
	const p = "/v1/server/outbound_traffic"
	req := PushOutboundTrafficRequest{
		Traffic: traffic,
	}
	r, err := c.Client.R().
		SetBody(req).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), err)
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return fmt.Errorf("failed to access %s: %s", path.Join(c.APIHost+p), string(body))
	}
	return nil
}
