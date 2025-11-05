package main

import (
    "testing"
	dns "nyasaki/dns-server/dns"
)

func TestBuildQuestion(t *testing.T) {
	var pkt []byte
	hdr := dns.DNSHeader{
		ID:      0x1337,
		QR:      false, // query
		Opcode:  0,
		QDCount: 1,
	}
	pkt = append(pkt, dns.BuildHeader(hdr)...)

	q := dns.DNSQuestion{
		Name:  "nyasaki.dev",
		Type:  1, // A
		Class: 1, // IN
	}
	names := make(map[string]int)

	pkt, err := dns.BuildQuestion(pkt, q, names)
	if err != nil {
		t.Fatalf("BuildQuestion failed: %v", err)
	}
	if len(pkt) < 12 {
		t.Fatalf("packet too short: %d", len(pkt))
	}

	_, e := dns.ParseQuestionPacket(pkt, len(pkt))
	if e != nil {
		t.Fatalf("BuildQuestion (Parse) failed: %v", e)
	}

	t.Logf("final packet (%d bytes): % X", len(pkt), pkt)
	t.Logf("name offsets: %#v", names)
}