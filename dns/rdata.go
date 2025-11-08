package dns

func ParseRdata(pkt []byte, type_code int) {
	switch type_code {
	case 1: //A

	case 2: //NS

	case 5: //CNAME

	case 6: //SOA

	case 12: //PTR

	case 15: //MX

	case 16: //TXT

	case 28: //AAAA

	case 33: //SRV

	case 64, 65, 257: //SVCB, HTTPS, CAA

	}
}
