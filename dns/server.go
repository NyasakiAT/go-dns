package dns

import (
	"fmt"
	"net"
	"nyasaki/dns-server/metrics"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/rs/zerolog/log"
)

func SetupConnection() (*net.UDPConn, error) {
	server, err := net.ResolveUDPAddr("udp4", ":53")
	if err != nil {
		log.Error().Msg("failed to reserve port (udp) '" + err.Error() + "'")
		return nil, err
	}

	sConn, err := net.ListenUDP("udp4", server)
	if err != nil {
		log.Error().Msg("failed to start listening (udp) '" + err.Error() + "'")
		return nil, err
	}

	log.Debug().Msg("Listening...")

	return sConn, nil
}

func ProcessQuestion(q DNSQuestionPacket, connection *net.UDPConn, cAddr *net.UDPAddr, cache *ristretto.Cache[string, CacheEntry], stats *metrics.Stats) {
	answers := CacheRetrieve(q, cache)
	ans := make([]byte, 0)
	names := make(map[string]int)

	if len(answers) > 1 {

		log.Debug().Msg("Cache hit")

		answer := DNSAnswerPacket{}

		header := DNSHeader{}
		header.QDCount = uint16(1)
		header.ANCount = uint16(len(answers))
		header.NSCount = uint16(0) // TODO
		header.ARCount = uint16(0) // TODO
		header.ID = q.Header.ID
		header.QR = true
		header.Opcode = q.Header.Opcode
		header.AA = false
		header.TC = false
		header.RD = false
		header.RA = false
		header.RCode = uint8(0) // TODO SET IF ERROR

		answer.Answers = answers
		answer.Questions = append([]DNSQuestion{}, q.Question)
		answer.Header = header

		a_pkt, err := BuildAnswerPacket(answer)
		if err != nil {
			log.Error().Msg("failed to rbuild answer packet '" + err.Error() + "'")
			stats.UpstreamErr.Add(1)
			return
		}
		ans = append(ans, a_pkt...)
		stats.CacheHits.Add(1)

	} else {

		// Create upstream here so every routine gets it own reply
		upstream, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")
		if err != nil {
			log.Error().Msg("failed to resolve upstream '" + err.Error() + "'")
			stats.UpstreamErr.Add(1)
			return
		}

		upConn, err := net.DialUDP("udp4", nil, upstream)
		if err != nil {
			log.Error().Msg("failed to open connection to upstream '" + err.Error() + "'")
			stats.UpstreamErr.Add(1)
			return
		}

		// Set deadline for sending request and send request
		upConn.SetWriteDeadline(time.Now().Add(2 * time.Second))

		pkt := BuildHeader(q.Header)
		pkt, err = BuildQuestion(pkt, q.Question, names)
		if err != nil {
			log.Error().Msg("failed to build question '" + err.Error() + "'")
			return
		}

		_, err = upConn.Write(pkt)
		if err != nil {
			log.Error().Msg("failed to transmit question to upstream '" + err.Error() + "'")
			return
		}

		ans := make([]byte, 4096)

		// Set read deadline and read answer
		_ = upConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n2, _, err := upConn.ReadFromUDP(ans)
		if err != nil {
			fmt.Println("SERVFAIL")
			return
		}

		upConn.Close()

		answer, err := ParseAnswerPacket(ans[:n2], n2)
		if err != nil {
			log.Error().Msg("failed to parse answer from upstream '" + err.Error() + "'")
			return
		}

		if len(answer.Answers) > 0 {
			CachePut(q, answer, cache)
			stats.CacheMisses.Add(1)
		}

	}

	_, err := connection.WriteToUDP(ans, cAddr)
	if err != nil {
		log.Error().Msg("failed to send answer to " + cAddr.String() + " '" + err.Error() + "'")
		return
	}

	stats.UpstreamOK.Add(1)
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

	udpConn, err := SetupConnection()
	if err != nil {
		log.Error().Msg("error setting up the udp server " + err.Error())
	}

	for {
		// Start reading from server socket
		n, cAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		question, err := ParseQuestionPacket(buffer[:n], n)
		if err != nil {
			log.Error().Msg("error parsing question from client: " + err.Error())
		}

		// Start gorouttine for answeing so we dont block
		go ProcessQuestion(question, udpConn, cAddr, cache, stats)
	}
}
