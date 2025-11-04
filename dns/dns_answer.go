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

	answer.Type = binary.BigEndian.Uint16(b[off : off+2]); off += 2
	answer.Class = binary.BigEndian.Uint16(b[off : off+2]); off += 2
	answer.TTL = binary.BigEndian.Uint32(b[off : off+4]); off += 4

	a_rdlength := binary.BigEndian.Uint16(b[off : off+2]); off += 2

	rdataStart := off
	rdataEnd := off + int(a_rdlength)

	fmt.Println("Len: ", a_rdlength, " Start: ", rdataStart, " End: ", rdataEnd)

	if rdataEnd > len(b) {
		return answer, 0, fmt.Errorf("short RDATA: need %d, have %d", rdataEnd, len(b))
	}

	answer.RDLength = a_rdlength
	answer.RData = b[rdataStart:rdataEnd]

	return answer, rdataEnd, nil
}

func BuildAnswer(pkt []byte, a DNSAnswer, names map[string]int) ([]byte, map[string]int, error) {

	pkt, names, _ = BuildNameCompressed(pkt, a.Name, names)

	qtype := []byte{byte(a.Type >> 8), byte(a.Type)}
	pkt = append(pkt, qtype...)

	qclass := []byte{byte(a.Class >> 8), byte(a.Class)}
	pkt = append(pkt, qclass...)

	qttl := uint16(a.TTL)
	pkt = append(pkt, byte(qttl))

	qrdl := []byte{byte(a.RDLength >> 8), byte(a.RDLength)}
	pkt = append(pkt, qrdl...)

	pkt = append(pkt, a.RData...)

	// Check if it can be decoded
	_, _, err := ParseAnswer(pkt, len(pkt))
	if err != nil {
		return pkt, names, fmt.Errorf("packet check failed: %v", err)
	}

	return pkt, names, nil
}

func BuildAnswerPaket(a_pkt DNSAnswerPacket) ([]byte, error) {
	pkt := make([]byte, 0, 4096)
	compression_values := make(map[string]int)

	header := BuildHeader(a_pkt.Header)
	pkt = append(pkt, header...)

	for i := 0; i < len(a_pkt.Questions); i++ {
		q, lbls, err := BuildQuestion(pkt, a_pkt.Questions[i], compression_values)
		compression_values = lbls
		if err != nil{
			fmt.Println("error while building answer packet, could not build question: ", err)
		}
		pkt = append(pkt, q...)
	}

	for i := 0; i < len(a_pkt.Answers); i++ {
		a, lbls, err := BuildAnswer(pkt, a_pkt.Answers[i], compression_values)
		compression_values = lbls
		if err != nil {
			fmt.Println("error while building answer packet, could not build answer: ", err)
		}
		pkt = append(pkt, a...)
	}

	_, err := ParseAnswerPacket(pkt, len(pkt))
	if err != nil {
		return pkt, fmt.Errorf("packet check failed: %v", err)
	}

	return pkt, nil
}
