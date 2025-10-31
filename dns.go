package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// Struct for DNS packet header
type DNSHeader struct {
	ID                                 uint16
	QR                                 bool  // query(0)/response(1)
	Opcode                             uint8 // 4 bits
	AA, TC, RD, RA                     bool
	Z                                  uint8 // 3 bits (must be 0 in classic DNS)
	RCode                              uint8 // 4 bits
	QDCount, ANCount, NSCount, ARCount uint16
}

// Parses the header section of the packet
func ParseHeader(b []byte) (DNSHeader, error) {
	if len(b) < 12 {
		return DNSHeader{}, fmt.Errorf("packet too short: %d < 12", len(b))
	}

	header := DNSHeader{}

	header.ID = binary.BigEndian.Uint16(b[0:2])

	flags := binary.BigEndian.Uint16(b[2:4])

	header.QR = ((flags >> 15) & 1) == 1
	header.Opcode = uint8((flags >> 11) & 15)
	header.AA = ((flags >> 10) & 1) == 1
	header.TC = ((flags >> 9) & 1) == 1
	header.RD = ((flags >> 8) & 1) == 1
	header.RA = ((flags >> 7) & 1) == 1
	header.Z = uint8((flags >> 4) & 7)
	header.RCode = uint8(flags & 15)

	header.QDCount = binary.BigEndian.Uint16(b[4:6])
	header.ANCount = binary.BigEndian.Uint16(b[6:8])
	header.NSCount = binary.BigEndian.Uint16(b[8:10])
	header.ARCount = binary.BigEndian.Uint16(b[10:12])
	return header, nil
}

// Build the header packet from the DNSHeader struct
func BuildHeader(header DNSHeader) []byte {
	flags := uint16(0)
	if header.QR {
		flags |= 1 << 15
	}
	flags |= (uint16(header.Opcode) & 15) << 11
	if header.AA {
		flags |= 1 << 10
	}
	if header.TC {
		flags |= 1 << 9
	}
	if header.RD {
		flags |= 1 << 8
	}
	if header.RA {
		flags |= 1 << 7
	}
	flags |= (uint16(header.Z) & 7) << 4
	flags |= uint16(header.RCode) & 15

	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], header.ID)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], header.QDCount)
	binary.BigEndian.PutUint16(out[6:8], header.ANCount)
	binary.BigEndian.PutUint16(out[8:10], header.NSCount)
	binary.BigEndian.PutUint16(out[10:12], header.ARCount)
	return out
}

func ParseName(msg []byte, off int) (string, int, error) {
	var labels []string
	start := off
	jumped := false

	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("out of bounds")
		}

		length := msg[off]

		// Name is a pointer
		if length&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated pointer")
			}

			// read 14-bit offset (first 2 bits are pointer indicator)
			pointer := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)

			// move to pointer target
			off = pointer

			// mark that we followed a pointer
			if !jumped {
				// original message continues after the pointer
				start += 2 
				jumped = true
			}
			continue
		}

		off++
		
		// end of name
		if length == 0 { 
			break
		}

		if off+int(length) > len(msg) {
			return "", 0, fmt.Errorf("label length overflow")
		}

		// Append to labels array for later joining
		labels = append(labels, string(msg[off:off+int(length)]))
		off += int(length)
	}

	// Joins labels with .
	name := strings.Join(labels, ".")

	// No pointer, just continue reading normally
	if !jumped {
		return name, off, nil
	}

	// Continue reading after pointer
	return name, start, nil
}

func main() {
	fmt.Println("Starting DNS")

	server, err := net.ResolveUDPAddr("udp4", ":53")
	client, err := net.ResolveUDPAddr("udp4", "9.9.9.9:53")

	if err != nil {
		fmt.Println("Error resolving address: ", err)
		return
	}

	s_conn, err := net.ListenUDP("udp4", server)
	c_conn, err := net.DialUDP("udp4", nil, client)
	if err != nil {
		fmt.Println("Error listening on UDP: ", err)
		return
	}

	defer s_conn.Close()

	buffer := make([]byte, 4096)
	for {

		// Start reading from server socket
		n, c_addr, err := s_conn.ReadFromUDP(buffer)
		if err != nil { continue }

		header, err := ParseHeader(buffer[:n])
		name, _, _ := ParseName(buffer[:n], 12)

		fmt.Println("REQ: ", header)
		fmt.Println("REQ: ", name)

		//TODO: Check cache

		q := make([]byte, n)
    	copy(q, buffer[:n])
		
		// Start gorouttine for answeing so we dont block
		go func(q []byte, client *net.UDPAddr) {

			// Set deadline for sending request and send request
			c_conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := c_conn.Write(q); err != nil{
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

			ans_header, err := ParseHeader(ans[:n])
			ans_name, _, _ := ParseName(ans[:n], 12)

			fmt.Println("ANS: ", ans_header)
			fmt.Println("ANS: ", ans_name)

			//Reply to the original client
			_, _ = s_conn.WriteToUDP(ans[:n2], client)
    	}(q, c_addr)

		if err != nil {
			fmt.Println("Errror receiving: ", err)
		}

		if strings.TrimSpace(string(buffer[0:n])) == "STOP" {
			fmt.Println("Exiting UDP server!")
			return
		}
	}
}
