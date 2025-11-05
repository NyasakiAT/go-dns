package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSAnswerPacket struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
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
		return q_pkt, fmt.Errorf("enountered error while parsing header: %v", h_err)
	}

	off := DNSHeaderSize
	questions := make([]DNSQuestion, 0, header.QDCount)

	for i := 0; i < int(header.QDCount); i++ {
		q, q_off, q_err := ParseQuestion(msg, off)
		if q_err != nil {
			return q_pkt, fmt.Errorf("enountered error while parsing question: %v", q_err)
		}
		questions = append(questions, q)
		off = q_off
	}

	answers := make([]DNSAnswer, 0, header.ANCount)

	for i := 0; i < int(header.ANCount); i++ {
		a, a_off, a_err := ParseAnswer(msg, off)
		if a_err != nil {
			return q_pkt, fmt.Errorf("enountered error while parsing answer: %v", a_err)
		}
		answers = append(answers, a)
		off = a_off
	}

	if int(header.ANCount) != len(answers) {
		return q_pkt, fmt.Errorf("answer lengths dont match")
	}

	q_pkt.Header = header
	q_pkt.Questions = questions
	q_pkt.Answers = answers

	return q_pkt, nil
}

func ParseAnswer(b []byte, start int) (DNSAnswer, int, error) {
	answer := DNSAnswer{}

	name, off, err := ParseName(b, start)
	if err != nil {
		return answer, 0, fmt.Errorf("error parsing name %v", err)
	}
	answer.Name = name

	answer.Type = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	answer.Class = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	answer.TTL = binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	a_rdlength := binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	rdataStart := off
	rdataEnd := off + int(a_rdlength)

	if rdataEnd > len(b) {
		return answer, 0, fmt.Errorf("short RDATA: need %d, have %d", rdataEnd, len(b))
	}

	answer.RDLength = a_rdlength
	answer.RData = b[rdataStart:rdataEnd]

	return answer, rdataEnd, nil
}

func BuildAnswer(pkt []byte, a DNSAnswer, names map[string]int) ([]byte, error) {
	ansStart := len(pkt)

	pkt, _ = BuildNameCompressed(pkt, a.Name, names)

	pkt = append(pkt, byte(a.Type>>8), byte(a.Type))

	pkt = append(pkt, byte(a.Class>>8), byte(a.Class))

	pkt = append(pkt, byte(a.TTL>>24), byte(a.TTL>>16), byte(a.TTL>>8), byte(a.TTL))

	pkt = append(pkt, byte(a.RDLength>>8), byte(a.RDLength))

	switch a.Type {
	case 2, 5, 12, 15, 33, 6: // NS, CNAME, PTR, MX, SRV, SOA

		// Roll back
		pkt = pkt[:ansStart]

		return pkt, fmt.Errorf("name-bearing RDATA not supported yet")
	}
	pkt = append(pkt, a.RData...)

	// Check if it can be decoded
	_, _, err := ParseAnswer(pkt, ansStart)
	if err != nil {

		// Roll back
		pkt = pkt[:ansStart]

		return pkt, fmt.Errorf("packet check failed: %v", err)
	}

	return pkt, nil
}

func BuildAnswerPaket(a_pkt DNSAnswerPacket) ([]byte, error) {

	// Reserve 12 for the header
	pkt := make([]byte, 12, 4096)
	compression_values := make(map[string]int)
	var err error

	for i := 0; i < len(a_pkt.Questions); i++ {
		pkt, err = BuildQuestion(pkt, a_pkt.Questions[i], compression_values)
		if err != nil {
			fmt.Println("error while building answer packet, could not build question: ", err)
		}
	}

	anCount := 0
	for i := 0; i < len(a_pkt.Answers); i++ {
		pkt, err = BuildAnswer(pkt, a_pkt.Answers[i], compression_values)
		if err != nil {
			fmt.Println("error while building answer packet, could not build answer: ", err)
		}else{
			anCount++
		}
	}

	_, err2 := ParseAnswerPacket(pkt, len(pkt))
	if err2 != nil {
		return pkt, fmt.Errorf("packet check failed: %v", err)
	}

	h := a_pkt.Header
	h.ANCount = uint16(anCount)
	header := BuildHeader(h)
	copy(pkt[:12], header)

	return pkt, nil
}
