package dns

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}
