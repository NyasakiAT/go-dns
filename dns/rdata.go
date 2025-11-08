package dns

import (
	"fmt"
)

func BuildRdata(ans []byte, raw []byte, type_code uint16, offset int, rdlen uint16, names map[string]int) ([]byte, error) {

	if offset < 0 || offset+int(rdlen) > len(raw) {
		return nil, fmt.Errorf("RDATA out of bounds: off=%d rdlen=%d len=%d", offset, rdlen, len(raw))
	}
	rdata := raw[offset : offset+int(rdlen)]

	switch type_code {
	case 1: //A
		if rdlen != 4 {
			return nil, fmt.Errorf("'A' record wrong rdlen")
		}

		ans = append(ans, rdata...)

	case 2: //NS
		// Needs the raw source packet because names might be compressed
		name, roff, err := ParseName(raw, offset)
		if err != nil {
			return nil, err
		}
		if roff > offset+int(rdlen) {
			return nil, fmt.Errorf("%d name overruns RDATA", type_code)
		}

		ans, _ = BuildNameCompressed(ans, name, names)

	case 5: //CNAME
		// Needs the raw source packet because names might be compressed
		name, roff, err := ParseName(raw, offset)
		if err != nil {
			return nil, err
		}
		if roff > offset+int(rdlen) {
			return nil, fmt.Errorf("%d name overruns RDATA", type_code)
		}

		ans, _ = BuildNameCompressed(ans, name, names)

	case 6: //SOA
		// Needs the raw source packet because names might be compressed
		mname, roff, err := ParseName(raw, offset)
		if err != nil {
			return nil, err
		}

		ans, _ = BuildNameCompressed(ans, mname, names)

		rname, roff, err := ParseName(raw, roff)
		if err != nil {
			return nil, err
		}

		if roff > offset+int(rdlen) {
			return nil, fmt.Errorf("%d name overruns RDATA", type_code)
		}

		// Needs the raw source packet because names might be compressed
		ans, _ = BuildNameCompressed(ans, rname, names)

		if len(raw) < roff+20 {
			return nil, fmt.Errorf("'SOA' short RDATA")
		}
		ans = append(ans, raw[roff:roff+20]...)

	case 12: //PTR
		name, roff, err := ParseName(raw, offset)
		if err != nil {
			return nil, err
		}

		if roff > offset+int(rdlen) {
			return nil, fmt.Errorf("%d name overruns RDATA", type_code)
		}

		ans, _ = BuildNameCompressed(ans, name, names)

	case 15: //MX
		if rdlen < 3 {
			return nil, fmt.Errorf("'MX' record wrong rdlen")
		}
		pref := rdata[:2]
		ans = append(ans, pref...)

		name, roff, err := ParseName(raw, offset+len(pref))
		if err != nil {
			return nil, err
		}

		if roff > offset+int(rdlen) {
			return nil, fmt.Errorf("%d name overruns RDATA", type_code)
		}

		ans, _ = BuildNameCompressed(ans, name, names)

	case 16: //TXT
		ans = append(ans, rdata...)

	case 28: //AAAA
		if rdlen != 16 {
			return nil, fmt.Errorf("'AAAA' record wrong rdlen")
		}
		ans = append(ans, rdata...)

	case 33: // SRV
		if rdlen < 7 { // 2+2+2 + at least one octet for name (can be 0 root)
			return nil, fmt.Errorf("SRV rdlen too small: %d", rdlen)
		}
		roff := offset

		// fixed fields: priority(2) + weight(2) + port(2)
		ans = append(ans, raw[roff:roff+6]...)
		roff += 6

		// target (compressed name)
		target, nOff, err := ParseName(raw, roff)
		if err != nil {
			return nil, err
		}
		if nOff > offset+int(rdlen) {
			return nil, fmt.Errorf("SRV target overruns RDATA: %d > %d", nOff, offset+int(rdlen))
		}
		ans, _ = BuildNameCompressed(ans, target, names)

	case 64, 65, 257: //SVCB, HTTPS, CAA
		return nil, fmt.Errorf("type SVCB, HTTPS, CAA not supported yet")

	default: //Opaque?
		ans = append(ans, rdata...)
	}

	return ans, nil
}
