package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type DNSQuestionPacket struct {
	Header   DNSHeader
	Question DNSQuestion
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func ParseQuestionPacket(b []byte, n int) (DNSQuestionPacket, error) {
	q_pkt := DNSQuestionPacket{}
	msg := b[:n]

	header, h_err := ParseHeader(msg)
	if h_err != nil {
		return q_pkt, fmt.Errorf("enountered error while parsing header: %d", h_err)
	}

	question, _, q_err := ParseQuestion(msg, DNSHeaderSize)
	if q_err != nil {
		return q_pkt, fmt.Errorf("enountered error while parsing question: %d", h_err)
	}

	q_pkt.Header = header
	q_pkt.Question = question

	return q_pkt, nil
}

func ParseQuestion(b []byte, start int) (DNSQuestion, int, error) {
	question := DNSQuestion{}

	name, off, err := ParseName(b, start)
	if err != nil {
		return question, 0, fmt.Errorf("error parsing name")
	}
	question.Name = name

	if off+4 > len(b) {
		return question, 0, fmt.Errorf("truncated question section")
	}

	q_type := binary.BigEndian.Uint16(b[off : off+2])
	question.Type = q_type

	q_class := binary.BigEndian.Uint16(b[off+2 : off+4])
	question.Class = q_class

	return question, off + 4, nil
}

func BuildQuestion(pkt []byte, q DNSQuestion, names map[string]int) ([]byte, map[string]int, error) {

	pkt, names, _ = BuildNameCompressed(pkt, q.Name, names)

	qtype := []byte{byte(q.Type >> 8), byte(q.Type)}
	pkt = append(pkt, qtype...)

	qclass := []byte{byte(q.Class >> 8), byte(q.Class)}
	pkt = append(pkt, qclass...)

	return pkt, names, nil
}
