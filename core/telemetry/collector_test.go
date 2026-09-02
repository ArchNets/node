package telemetry

import (
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestCollectorRecordAndDrain(t *testing.T) {
	c := NewCollector(100)

	now := time.Now().Unix()

	// Ingest connection 1
	c.Record(panel.DestinationRecord{
		UID:             20306,
		ClientIP:        "5.126.109.232",
		DestinationHost: "i.instagram.com",
		DestinationIP:   "157.240.22.174",
		Port:            443,
		Protocol:        "tls",
		Blocked:         false,
		Hits:            1,
		Timestamp:       now,
	})

	// Ingest connection 2 (same key, should aggregate hits)
	c.Record(panel.DestinationRecord{
		UID:             20306,
		ClientIP:        "5.126.109.232",
		DestinationHost: "i.instagram.com",
		DestinationIP:   "157.240.22.174",
		Port:            443,
		Protocol:        "tls",
		Blocked:         false,
		Hits:            4,
		Timestamp:       now + 1,
	})

	// Ingest connection 3 (blocked destination)
	c.Record(panel.DestinationRecord{
		UID:             20306,
		ClientIP:        "5.126.109.232",
		DestinationHost: "test-gateway.instagram.com",
		DestinationIP:   "157.240.22.175",
		Port:            443,
		Protocol:        "quic",
		Blocked:         true,
		Hits:            1,
		Timestamp:       now,
	})

	// Ingest connection 4 (different user)
	c.Record(panel.DestinationRecord{
		UID:             10001,
		ClientIP:        "1.2.3.4",
		DestinationHost: "google.com",
		DestinationIP:   "142.250.180.206",
		Port:            443,
		Protocol:        "tls",
		Blocked:         false,
		Hits:            1,
		Timestamp:       now,
	})

	records := c.Drain()
	assert.Len(t, records, 3)

	var instagramHits int
	var blockedHits int
	var googleHits int

	for _, r := range records {
		if r.DestinationHost == "i.instagram.com" {
			instagramHits = r.Hits
			assert.Equal(t, int64(20306), r.UID)
			assert.False(t, r.Blocked)
		} else if r.DestinationHost == "test-gateway.instagram.com" {
			blockedHits = r.Hits
			assert.Equal(t, int64(20306), r.UID)
			assert.True(t, r.Blocked)
		} else if r.DestinationHost == "google.com" {
			googleHits = r.Hits
			assert.Equal(t, int64(10001), r.UID)
		}
	}

	assert.Equal(t, 5, instagramHits) // 1 + 4
	assert.Equal(t, 1, blockedHits)
	assert.Equal(t, 1, googleHits)

	// Second drain should be empty
	emptyRecords := c.Drain()
	assert.Nil(t, emptyRecords)
}

func TestCollectorCapacityCapping(t *testing.T) {
	c := NewCollector(2) // max 2 keys

	c.Record(panel.DestinationRecord{UID: 1, DestinationHost: "a.com", Port: 80})
	c.Record(panel.DestinationRecord{UID: 2, DestinationHost: "b.com", Port: 80})
	c.Record(panel.DestinationRecord{UID: 3, DestinationHost: "c.com", Port: 80}) // should be dropped

	records := c.Drain()
	assert.Len(t, records, 2)
}
