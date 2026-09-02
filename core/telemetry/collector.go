package telemetry

import (
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
)

// RecordKey represents the unique rollup key for connection telemetry within an aggregation window
type RecordKey struct {
	UID             int64
	DestinationHost string
	DestinationIP   string
	Port            int
	Protocol        string
	Blocked         bool
}

type RecordValue struct {
	ClientIP  string
	Hits      int
	Timestamp int64
}

// Collector provides thread-safe, bounded, in-memory deduplication and aggregation of connection telemetry
type Collector struct {
	mu      sync.Mutex
	buffer  map[RecordKey]*RecordValue
	maxSize int
}

const (
	DefaultMaxBufferSize = 10000
)

var (
	globalCollector *Collector
	initOnce        sync.Once
)

// GetGlobalCollector returns the singleton telemetry collector instance
func GetGlobalCollector() *Collector {
	initOnce.Do(func() {
		globalCollector = NewCollector(DefaultMaxBufferSize)
	})
	return globalCollector
}

// NewCollector creates a new Collector with bounded buffer capacity
func NewCollector(maxSize int) *Collector {
	if maxSize <= 0 {
		maxSize = DefaultMaxBufferSize
	}
	return &Collector{
		buffer:  make(map[RecordKey]*RecordValue),
		maxSize: maxSize,
	}
}

// Record ingests a connection destination event, aggregating hits in-memory
func (c *Collector) Record(rec panel.DestinationRecord) {
	if c == nil || rec.UID <= 0 {
		return
	}

	host := strings.ToLower(strings.TrimSpace(rec.DestinationHost))
	destIP := strings.TrimSpace(rec.DestinationIP)
	if destIP == "" && strings.Count(host, ".") == 3 {
		// Host is directly an IPv4 address
		destIP = host
	}
	proto := strings.ToLower(strings.TrimSpace(rec.Protocol))
	if proto == "" {
		proto = "tcp"
	}

	key := RecordKey{
		UID:             rec.UID,
		DestinationHost: host,
		DestinationIP:   destIP,
		Port:            rec.Port,
		Protocol:        proto,
		Blocked:         rec.Blocked,
	}

	now := rec.Timestamp
	if now <= 0 {
		now = time.Now().Unix()
	}

	hits := rec.Hits
	if hits <= 0 {
		hits = 1
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if val, ok := c.buffer[key]; ok {
		val.Hits += hits
		val.Timestamp = now
		if rec.ClientIP != "" {
			val.ClientIP = rec.ClientIP
		}
	} else {
		// Cap buffer to prevent unbound growth if backend is unreachable
		if len(c.buffer) >= c.maxSize {
			return
		}
		c.buffer[key] = &RecordValue{
			ClientIP:  rec.ClientIP,
			Hits:      hits,
			Timestamp: now,
		}
	}
}

// Drain atomically swaps the internal buffer and returns aggregated records for batch dispatch
func (c *Collector) Drain() []panel.DestinationRecord {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return nil
	}

	old := c.buffer
	c.buffer = make(map[RecordKey]*RecordValue)
	c.mu.Unlock()

	records := make([]panel.DestinationRecord, 0, len(old))
	for k, v := range old {
		records = append(records, panel.DestinationRecord{
			UID:             k.UID,
			ClientIP:        v.ClientIP,
			DestinationHost: k.DestinationHost,
			DestinationIP:   k.DestinationIP,
			Port:            k.Port,
			Protocol:        k.Protocol,
			Blocked:         k.Blocked,
			Hits:            v.Hits,
			Timestamp:       v.Timestamp,
		})
	}
	return records
}
