package dns

import "fmt"

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func ParseQuestion(b []byte) (DNSQuestion, error) {
	question := DNSQuestion{}

	fmt.Println("TODO PARSE")

	return question, nil
}

func BuildQuestion(header DNSQuestion) []byte {

	fmt.Println("TODO BUILD")

	return nil
}
