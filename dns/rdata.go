package dns

import (
	"encoding/binary"
	"fmt"
)

type MXData struct {
	Pref uint16
	Host string
}

type SOAData struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

type SRVData struct {
	Pri, Wt, Port uint16
	Target        string
}

type RData struct {
	Kind   uint16 // same as Type
	A      [4]byte
	AAAA   [16]byte
	Name   string // NS/CNAME/PTR target
	MX     MXData
	SRV    SRVData
	SOA    SOAData
	TXT    [][]byte
	Opaque []byte // fallback
}

func ParseRdata(pkt []byte, start int, rdlen uint16, atype uint16) (RData, error) {
	rdat := RData{}
	end := start + int(rdlen)
	if end > len(pkt) {
		return rdat, fmt.Errorf("short RDATA")
	}
	data := pkt[start:end]

	switch atype {
	case 1: //A
		if len(data) != 4 {
			return rdat, fmt.Errorf("'A' record wrong rdlen")
		}

		var a [4]byte
		copy(a[:], data[:start+4])
		rdat.A = a

	case 2: //NS
		name, roff, err := ParseName(pkt, start)
		if err != nil {
			return rdat, err
		}
		if roff > end {
			return rdat, fmt.Errorf("%d name overruns RDATA", atype)
		}

		rdat.Name = name

	case 5: //CNAME
		name, roff, err := ParseName(pkt, start)
		if err != nil {
			return rdat, err
		}
		if roff > end {
			return rdat, fmt.Errorf("%d name overruns RDATA", atype)
		}

		rdat.Name = name

	case 6: //SOA
		mname, roff, err := ParseName(pkt, start)
		if err != nil {
			return rdat, err
		}

		rname, roff, err := ParseName(pkt, roff)
		if err != nil {
			return rdat, err
		}

		if roff > end {
			return rdat, fmt.Errorf("%d name overruns RDATA", atype)
		}

		if end < roff+20 {
			return rdat, fmt.Errorf("'SOA' short RDATA")
		}

		serial := binary.BigEndian.Uint32(pkt[roff : roff+4])
		roff += 4
		refresh := binary.BigEndian.Uint32(pkt[roff : roff+4])
		roff += 4
		retry := binary.BigEndian.Uint32(pkt[roff : roff+4])
		roff += 4
		expire := binary.BigEndian.Uint32(pkt[roff : roff+4])
		roff += 4
		minimum := binary.BigEndian.Uint32(pkt[roff : roff+4])
		roff += 4

		soa := SOAData{
			MName: mname, RName: rname,
			Serial: serial, Refresh: refresh, Retry: retry, Expire: expire, Minimum: minimum,
		}

		rdat.SOA = soa

	case 12: //PTR
		name, roff, err := ParseName(pkt, start)
		if err != nil {
			return rdat, err
		}

		if roff > end {
			return rdat, fmt.Errorf("%d name overruns RDATA", atype)
		}

		rdat.Name = name

	case 15: //MX
		offset := start

		if rdlen < 3 {
			return rdat, fmt.Errorf("'MX' record wrong rdlen")
		}

		pref := binary.BigEndian.Uint16(pkt[offset : offset+2])
		offset += 2

		name, roff, err := ParseName(pkt, offset)
		if err != nil {
			return rdat, err
		}

		if roff > offset+int(rdlen) {
			return rdat, fmt.Errorf("%d name overruns RDATA", atype)
		}

		mxdata := MXData{Pref: pref, Host: name}
		rdat.MX = mxdata

	case 16: //TXT
		end := start + int(rdlen)
		if end > len(pkt) {
			return rdat, fmt.Errorf("TXT short RDATA: need %d, have %d", end, len(pkt))
		}

		var txts [][]byte

		// Each TXT record can contain multiple <character-string> elements.
		// Each one starts with a length byte followed by that many bytes.
		for i := 0; i < len(data); {
			if i >= len(data) {
				return rdat, fmt.Errorf("TXT malformed (truncated length byte)")
			}
			l := int(data[i])
			i++
			if i+l > len(data) {
				return rdat, fmt.Errorf("TXT malformed (length %d exceeds remaining %d)", l, len(data)-i)
			}
			txts = append(txts, append([]byte(nil), data[i:i+l]...))
			i += l
		}

		rdat.TXT = txts

	case 28: //AAAA
		if len(data) != 16 {
			return rdat, fmt.Errorf("'AAAA' record wrong rdlen")
		}
		var a6 [16]byte
		copy(a6[:], pkt[start:start+16])
		rdat.AAAA = a6

	case 33: // SRV
		if len(data) < 7 { // 2+2+2 + at least one octet for name (can be 0 root)
			return rdat, fmt.Errorf("SRV rdlen too small: %d", rdlen)
		}
		roff := start

		priority := binary.BigEndian.Uint16(pkt[roff : roff+2])
		roff += 2
		weight := binary.BigEndian.Uint16(pkt[roff : roff+2])
		roff += 2
		port := binary.BigEndian.Uint16(pkt[roff : roff+2])
		roff += 2

		// target (compressed name)
		target, nOff, err := ParseName(pkt, roff)
		if err != nil {
			return rdat, err
		}
		if nOff > end {
			return rdat, fmt.Errorf("SRV target overruns RDATA: %d > %d", nOff, start+int(rdlen))
		}

		srv := SRVData{Pri: priority, Wt: weight, Port: port, Target: target}
		rdat.SRV = srv

	case 64, 65, 257: //SVCB, HTTPS, CAA
		return rdat, fmt.Errorf("type SVCB, HTTPS, CAA not supported yet")

	default:
		rdat.Opaque = append([]byte(nil), data...)
	}

	return rdat, nil
}

func BuildRdata(ans []byte, dat RData, type_code uint16, names map[string]int) ([]byte, error) {

	switch type_code {
	case 1: //A
		a := dat.A
		ans = append(ans, a[:]...)

	case 2: //NS
		ans, _ = BuildNameCompressed(ans, dat.Name, names)

	case 5: //CNAME
		ans, _ = BuildNameCompressed(ans, dat.Name, names)

	case 6: //SOA
		ans, _ = BuildNameCompressed(ans, dat.SOA.MName, names)
		ans, _ = BuildNameCompressed(ans, dat.SOA.RName, names)
		ans = append(ans, byte(dat.SOA.Serial))

	case 12: //PTR
		ans, _ = BuildNameCompressed(ans, dat.Name, names)

	case 15: //MX
		ans = append(ans, byte(dat.MX.Pref))
		ans, _ = BuildNameCompressed(ans, dat.MX.Host, names)

	case 16: //TXT
		// write RDATA
		for _, s := range dat.TXT {
			ans = append(ans, byte(len(s)))
			ans = append(ans, s...)
		}

	case 28: //AAAA
		a6 := dat.AAAA
		ans = append(ans, a6[:]...)

	case 33: // SRV
		ans = append(ans, byte(dat.SRV.Pri))
		ans = append(ans, byte(dat.SRV.Wt))
		ans = append(ans, byte(dat.SRV.Port))
		ans, _ = BuildNameCompressed(ans, dat.SRV.Target, names)

	case 64, 65, 257: //SVCB, HTTPS, CAA
		return ans, fmt.Errorf("type SVCB, HTTPS, CAA not supported yet")

	default: //Opaque?
		ans = append(ans, dat.Opaque...)
	}

	return ans, nil
}
