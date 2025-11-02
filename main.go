package main

import (
	"fmt"
	"net"
	dns "nyasaki/dns-server/dns"
	"time"
)

func main() {
	fmt.Println("Starting DNS")

	server, err := net.ResolveUDPAddr("udp4", ":53")
	if err != nil {
		fmt.Println("Error resolving address: ", err)
		return
	}

	s_conn, err := net.ListenUDP("udp4", server)
	if err != nil {
		fmt.Println("Error listening on UDP: ", err)
		return
	}

	defer s_conn.Close()

	buffer := make([]byte, 4096)
	for {

		// Start reading from server socket
		n, c_addr, err := s_conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		question, _ := dns.ParseQuestionPacket(buffer[:n], n)

		fmt.Println("Q: ", question.Question.Name)
		fmt.Println("Q: ", question.Question.Type)

		//TODO: Check cache

		q := make([]byte, n)
		copy(q, buffer[:n])

		// Start gorouttine for answeing so we dont block
		go func(q []byte, client *net.UDPAddr) {
			// Create client here so every routine gets it own reply
			client, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")
			c_conn, err := net.DialUDP("udp4", nil, client)

			// Set deadline for sending request and send request
			c_conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := c_conn.Write(q); err != nil {
				return
			}

			ans := make([]byte, 4096)

			// Set read deadline and read answer
			_ = c_conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n2, _, err := c_conn.ReadFromUDP(ans)
			if err != nil {
				//TODO: Send SERVFAIL here
				return
			}

			answer, _ := dns.ParseAnswerPacket(ans[:n2], n2)
			fmt.Println("A: ", len(answer.Answers))

			_, _ = s_conn.WriteToUDP(ans[:n2], client)
			c_conn.Close()
		}(q, c_addr)

		if err != nil {
			fmt.Println("Errror receiving: ", err)
		}
	}
}
