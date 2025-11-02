package dns

import "fmt"

type DNSAnswer struct  {
    Name     string
    Type     uint16
    Class    uint16
    TTL      uint32
    RDLength uint16
    RData    []byte
}

func ParseAnswer(b []byte) (DNSAnswer, error) {
	answer := DNSAnswer{}

	fmt.Println("TODO PARSE")

	return answer, nil
}

func BuildAnswer(header DNSAnswer) []byte {

	fmt.Println("TODO BUILD")

	return nil
}