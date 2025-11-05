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
		log.Error().Msg("Error resolving address: " + err.Error())
		return nil, err
	}

	sConn, err := net.ListenUDP("udp4", server)
	if err != nil {
		log.Error().Msg("Error listening on UDP: " + err.Error())
		return nil, err
	}

	/*defer func() {
		cerr := sConn.Close()
		if err == nil {
			err = cerr
		}
	}()*/

	return sConn, nil
}

func ProcessQuestion(q []byte, connection *net.UDPConn, cAddr *net.UDPAddr) {
	// Create upstream here so every routine gets it own reply
	upstream, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")
	upConn, err := net.DialUDP("udp4", nil, upstream)

	// Set deadline for sending request and send request
	upConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := upConn.Write(q); err != nil {
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
		log.Error().Msg("error parsing answer from client: " + err.Error())
	}

	BuildAnswerPaket(answer)

	log.Debug().Msg("A: Questions:" + string(len(answer.Questions)) + " Answers:" + string(len(answer.Answers)))

	_, _ = connection.WriteToUDP(ans[:n2], cAddr)
}

func StartServer() error {
	buffer := make([]byte, 4096)

	udpConn, err := SetupConnection()
	if err != nil {
		log.Error().Msg("error parsing question from client: " + err.Error())
	}

	log.Debug().Msg("Listening...")

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
