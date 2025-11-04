package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const DNSHeaderSize = 12

func ParseName(msg []byte, off int) (string, int, error) {
	var labels []string
	start := off
	jumped := false

	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("oob")
		}
		length := msg[off]

		// Name is a pointer
		if length&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			pointer := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if pointer >= len(msg) {
				return "", 0, fmt.Errorf("bad ptr %d", pointer)
			}

			if !jumped {
				// original message continues after the pointer
				start += 2
				jumped = true
			}
			// read 14-bit offset (first 2 bits are pointer indicator)
			//pointer := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)

			// move to pointer target
			off = pointer

			// mark that we followed a pointer
			
			continue
		}

		off++

		// end of name
		if length == 0 {
			break
		}

		if off+int(length) > len(msg) {
			return "", 0, fmt.Errorf("label length overflow")
		}

		// Append to labels array for later joining
		labels = append(labels, string(msg[off:off+int(length)]))
		off += int(length)
	}

	// Joins labels with .
	name := strings.Join(labels, ".")

	// No pointer, just continue reading normally
	if !jumped {
		return name, off, nil
	}

	// Continue reading after pointer
	return name, start, nil
}

func BuildNameCompressed(pkt []byte, name string, names map[string]int) ([]byte, map[string]int, int) {
	//fmt.Println("Got map: ", names)

	name = strings.TrimSuffix(name, ".")
	if name == "" {
		start := len(pkt)
		pkt = append(pkt, 0)
		return pkt, names, start
	}

	labels := strings.Split(name, ".")

	cut := len(labels)
	ptrOff := -1
	for i := 0; i < len(labels); i++ {
		suf := strings.Join(labels[i:], ".")
		if off, ok := names[suf]; ok {
			cut = i
			ptrOff = off
			break
		}
	}

	start := len(pkt)

	for i := 0; i < cut; i++ {
		suf := strings.Join(labels[i:], ".")
		if _, ok := names[suf]; !ok {
			fmt.Println("label: ", suf, " offset: ", len(pkt))
			names[suf] = len(pkt)
		}
		lab := labels[i]
		pkt = append(pkt, byte(len(lab)))
		pkt = append(pkt, lab...)
	}

	if cut == len(labels) {
		// wrote full name, terminate
		pkt = append(pkt, 0)
	} else {
		// emit single pointer; NO 0x00 before a pointer
		p := 0xC000 | ptrOff
		pkt = append(pkt, byte(p>>8), byte(p))
	}

	if _, ok := names[name]; !ok {
		names[name] = start
	}

	return pkt, names, start
}
