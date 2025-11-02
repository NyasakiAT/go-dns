package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSAnswerPacket struct {
	Header DNSHeader
	Answers []DNSAnswer
}

type DNSAnswer struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func ParseAnswerPacket(b []byte, n int) (DNSAnswerPacket, error) {
	q_pkt := DNSAnswerPacket{}
	msg := b[:n]

	header, h_err := ParseHeader(msg)
	if h_err != nil {
		fmt.Println("enountered error while parsing header: ", h_err)
	}

	off := 12
	for i := 0; i < int(header.QDCount); i++ {
		_, q_off, err := ParseQuestion(msg, off)
		if err != nil { /* handle */ }
		off = q_off
	}

	answers := make([]DNSAnswer, 0, header.ANCount)
	for i := 0; i < int(header.ANCount); i++{
		answer, a_off, a_err := ParseAnswer(msg, off)
		if a_err != nil {
			fmt.Println("enountered error while parsing answer: ", a_err)
		}
		answers = append(answers, answer)
		off = a_off
	}

	if int(header.ANCount) != len(answers) {
		fmt.Println("Answer lengths dont match")
	}

	q_pkt.Header = header
	q_pkt.Answers = answers

	return q_pkt, nil
}

func ParseAnswer(b []byte, start int) (DNSAnswer, int, error) {
	answer := DNSAnswer{}

	name, off, err := ParseName(b, start)
	if err != nil {
		return answer, 0, fmt.Errorf("error parsing name")
	}
	answer.Name = name

	answer.Type = binary.BigEndian.Uint16(b[off : off+2])
	answer.Class = binary.BigEndian.Uint16(b[off+2 : off+4])
	answer.TTL = binary.BigEndian.Uint32(b[off+4 : off+8])

	a_rdlength := binary.BigEndian.Uint16(b[off+8 : off+10])
	
	rdataStart  := off + 10
    rdataEnd    := rdataStart + int(a_rdlength)

    if rdataEnd > len(b) {
        return answer, 0, fmt.Errorf("short RDATA: need %d, have %d", rdataEnd, len(b))
    }

	answer.RDLength = a_rdlength
	answer.RData = b[rdataStart:rdataEnd]

	return answer, rdataEnd, nil
}

func BuildAnswer(header DNSAnswer) []byte {

	fmt.Println("TODO BUILD")

	return nil
}
