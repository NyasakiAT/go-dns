package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type DNSHeader struct {
	ID                                 uint16
	QR                                 bool  // query(0)/response(1)
	Opcode                             uint8 // 4 bits
	AA, TC, RD, RA                     bool
	Z                                  uint8 // 3 bits (must be 0 in classic DNS)
	RCode                              uint8 // 4 bits
	QDCount, ANCount, NSCount, ARCount uint16
}

func ParseHeader(b []byte) (DNSHeader, error) {
	if len(b) < 12 {
		return DNSHeader{}, fmt.Errorf("Packet too short: %d < 12", len(b))
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

func ParseName(msg []byte, off int) (string, int, error){
var name string
    for {
        if off >= len(msg) {
            return "", 0, fmt.Errorf("out of bounds")
        }

        length := int(msg[off])
        off++

        if length == 0 { // end of name
            break
        }

        if off+length > len(msg) {
            return "", 0, fmt.Errorf("bad length")
        }

        if len(name) > 0 {
            name += "."
        }
        name += string(msg[off : off+length])
        off += length
    }
    return name, off, nil
}

func main() {
	fmt.Println("Starting DNS")

	server, err := net.ResolveUDPAddr("udp4", ":53")
	if err != nil {
		fmt.Errorf("Error resolving address: %q", err)
		return
	}

	connection, err := net.ListenUDP("udp4", server)
	if err != nil {
		fmt.Errorf("Error listening on UDP: %q", err)
		return
	}

	defer connection.Close()

	buffer := make([]byte, 32)
	for {
		n, _, err := connection.ReadFromUDP(buffer)

		header, err := ParseHeader(buffer[:n])
		name, _, _ := ParseName(buffer[:n], 12)

		fmt.Println(header)
		fmt.Println(name)

		if err != nil {
			fmt.Errorf("Errror receiving: %q", err)
		}

		if strings.TrimSpace(string(buffer[0:n])) == "STOP" {
			fmt.Println("Exiting UDP server!")
			return
		}
	}
}
