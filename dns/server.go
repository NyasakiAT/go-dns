package dns

import (
	"fmt"
	"net"
	"time"

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

func ProcessQuestion(q []byte, connection *net.UDPConn, cAddr *net.UDPAddr) {
	// Create upstream here so every routine gets it own reply
	upstream, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")
	if err != nil {
		log.Error().Msg("failed to resolve upstream '" + err.Error() + "'")
		return
	}

	upConn, err := net.DialUDP("udp4", nil, upstream)
	if err != nil {
		log.Error().Msg("failed to open connection to upstream '" + err.Error() + "'")
		return
	}

	// Set deadline for sending request and send request
	upConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := upConn.Write(q); err != nil {
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

	// DEBUG ---
	BuildAnswerPaket(answer)

	log.Debug().Msg("A: Questions:" + string(len(answer.Questions)) + " Answers:" + string(len(answer.Answers)))
	// ---

	_, err = connection.WriteToUDP(ans[:n2], cAddr)
	if err != nil {
		log.Error().Msg("failed to send answer to " + cAddr.String() + " '" + err.Error() + "'")
		return
	}
}

func StartServer() error {
	buffer := make([]byte, 4096)

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

		log.Info().Msg("Request from " + cAddr.String() + " Q: " + question.Question.Name)

		//TODO: Check cache

		q := make([]byte, n)
		copy(q, buffer[:n])

		// Start gorouttine for answeing so we dont block
		go ProcessQuestion(q, udpConn, cAddr)
	}
}
