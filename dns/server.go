package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"nyasaki/dns-server/metrics"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/rs/zerolog/log"
)

type pendEntry struct {
	addr  *net.UDPAddr
	orig  uint16
	key   string // cache key for this query
	exp   int64  // mono nanos
	inUse uint32
}

var pending [65536]pendEntry
var idCursor uint32 // atomically incremented

func freeUpID(id uint16) { atomic.StoreUint32(&pending[id].inUse, 0) }

func allocUpID(now int64) (uint16, bool) {
	for i := 0; i < 1024; i++ {
		id := uint16(atomic.AddUint32(&idCursor, 1))
		slot := &pending[id]
		if atomic.CompareAndSwapUint32(&slot.inUse, 0, 1) {
			slot.exp = now + int64(250*time.Millisecond) // your timeout
			return id, true
		}
	}
	return 0, false
}

func ServeFromCache(q DNSQuestionPacket, conn *net.UDPConn, cAddr *net.UDPAddr,
	cache *ristretto.Cache[string, CacheEntry], stats *metrics.Stats) bool {

	answers := CacheRetrieve(q, cache)
	if len(answers) == 0 {
		return false
	}

	hdr := DNSHeader{
		ID:      q.Header.ID,
		QR:      true,
		Opcode:  q.Header.Opcode,
		AA:      false,
		TC:      false,
		RD:      q.Header.RD, // reflect client
		RA:      true,
		RCode:   0,
		QDCount: 1,
		ANCount: uint16(len(answers)),
		NSCount: 0,
		ARCount: 0,
	}
	resp := DNSAnswerPacket{Header: hdr, Questions: []DNSQuestion{q.Question}, Answers: answers}
	wire, err := BuildAnswerPacket(resp)
	if err != nil {
		return false
	}
	_, _ = conn.WriteToUDP(wire, cAddr)
	return true
}

func UpstreamReader(udpConn, upConn *net.UDPConn, cache *ristretto.Cache[string, CacheEntry]) {
	buf := make([]byte, 4096)
	for {
		n, _, err := upConn.ReadFromUDP(buf)
		if err != nil || n < 2 {
			continue
		}

		upID := binary.BigEndian.Uint16(buf[:2])
		slot := &pending[upID]
		if atomic.LoadUint32(&slot.inUse) == 0 {
			continue
		}

		// restore original client ID
		binary.BigEndian.PutUint16(buf[:2], slot.orig)

		// parse + cache
		ans, err := ParseAnswerPacket(buf[:n], n)
		if err == nil && len(ans.Answers) > 0 && slot.key != "" {
			CachePutKey(slot.key, ans, cache) // implement: put by key directly
		}

		_, _ = udpConn.WriteToUDP(buf[:n], slot.addr)
		atomic.StoreUint32(&slot.inUse, 0)
	}
}

func SetupConnection() (*net.UDPConn, *net.UDPConn, error) {
	server, err := net.ResolveUDPAddr("udp4", ":53")
	if err != nil {
		log.Error().Msg("failed to reserve port (udp) '" + err.Error() + "'")
		return nil, nil, err
	}

	sConn, err := net.ListenUDP("udp4", server)
	if err != nil {
		log.Error().Msg("failed to start listening (udp) '" + err.Error() + "'")
		return nil, nil, err
	}

	sConn.SetReadBuffer(1 << 20)
	sConn.SetWriteBuffer(1 << 20)

	// Create upstream here so every routine gets it own reply
	upstream, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")
	if err != nil {
		log.Error().Msg("failed to resolve upstream '" + err.Error() + "'")
	}

	upConn, err := net.DialUDP("udp4", nil, upstream)
	if err != nil {
		log.Error().Msg("failed to open connection to upstream '" + err.Error() + "'")
	}

	log.Debug().Msg("Listening...")

	return sConn, upConn, nil
}
func CacheKeyFromQuestion(q DNSQuestionPacket) string {
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Question.Name), q.Question.Type, q.Question.Class)
}

func Sweeper() {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for now := range t.C {
		nn := now.UnixNano()
		for i := 0; i < len(pending); i++ {
			s := &pending[i]
			if atomic.LoadUint32(&s.inUse) == 1 && s.exp < nn {
				atomic.StoreUint32(&s.inUse, 0)
			}
		}
	}
}

func StartServer(stats *metrics.Stats) error {
	buffer := make([]byte, 4096)
	cache, err := ristretto.NewCache(
		&ristretto.Config[string, CacheEntry]{
			NumCounters: 1e5,
			MaxCost:     1 << 30,
			BufferItems: 64,
		},
	)
	if err != nil {
		log.Error().Msg("failed to add to cache '" + err.Error() + "'")
	}

	udpConn, upConn, err := SetupConnection()
	if err != nil {
		log.Error().Msg("error setting up the udp server " + err.Error())
	}

	go UpstreamReader(udpConn, upConn, cache /* & stats if needed */)
	go Sweeper()

	for {
		n, cAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		// clone the packet before any mutation
		pkt := make([]byte, n)
		copy(pkt, buffer[:n])

		// parse question
		q, err := ParseQuestionPacket(pkt, n)
		if err != nil {
			continue
		}

		// try cache
		if ServeFromCache(q, udpConn, cAddr, cache, stats) {
			stats.CacheHits.Add(1)
			continue
		}
		stats.CacheMisses.Add(1)

		// ID remap + pending bookkeeping
		orig := binary.BigEndian.Uint16(pkt[:2])
		now := time.Now().UnixNano()
		upID, ok := allocUpID(now)
		if !ok { /* optionally SERVFAIL */
			continue
		}

		key := CacheKeyFromQuestion(q) // implement once; same as you used for CacheRetrieve/Put
		slot := &pending[upID]
		slot.addr = cAddr
		slot.orig = orig
		slot.key = key
		slot.exp = now + int64(250*time.Millisecond)

		binary.BigEndian.PutUint16(pkt[:2], upID)
		_, _ = upConn.Write(pkt)
	}
}
