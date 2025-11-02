package dns

import (
	"encoding/binary"
	"strings"
	"fmt"
)

func ParseName(msg []byte, off int) (string, int, error) {
	var labels []string
	start := off
	jumped := false

	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("out of bounds")
		}

		length := msg[off]

		// Name is a pointer
		if length&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated pointer")
			}

			// read 14-bit offset (first 2 bits are pointer indicator)
			pointer := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)

			// move to pointer target
			off = pointer

			// mark that we followed a pointer
			if !jumped {
				// original message continues after the pointer
				start += 2
				jumped = true
			}
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