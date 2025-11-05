package main

import (
    "testing"
	"strings"
	"fmt"
	dns "nyasaki/dns-server/dns"
)

func TestParseName(t *testing.T) {
	tests := []struct {
		name     string
		msg      []byte
		offset   int
		wantName string
		wantNext int
		wantErr  bool
	}{
		{
			name:     "simple uncompressed",
			msg:      []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			offset:   0,
			wantName: "www.google.com",
			wantNext: 16,
		},
		{
			name: "compressed pointer to 0x0C",
			msg: []byte{
				3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, // 0–15
				0xC0, 0x00, // pointer to offset 0
			},
			offset:   16,
			wantName: "www.google.com",
			wantNext: 18,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotNext, err := dns.ParseName(tt.msg, tt.offset)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotName != tt.wantName {
				t.Fatalf("got name %q, want %q", gotName, tt.wantName)
			}
			if gotNext != tt.wantNext {
				t.Fatalf("got next %d, want %d", gotNext, tt.wantNext)
			}
		})
	}
}

func TestBuildNameCompressed(t *testing.T) {
	tests := []struct {
		name       string
		seed       map[string]int
		input      string
		wantHexHas string // quick contains check
		wantEnd    bool   // ends with 00 when no compression
	}{
		{
			name:       "full write no compression",
			seed:       map[string]int{},
			input:      "www.google.com",
			wantHexHas: "03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00",
			wantEnd:    true,
		},
		{
			name:       "compressed using existing suffix",
			seed:       map[string]int{"google.com": 12},
			input:      "mail.google.com",
			wantHexHas: "04 6d 61 69 6c c0 0c", // 04 "mail" + C0 0C pointer
			wantEnd:    false,                   // no 00 before pointer
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := make([]byte, 0, 128)
			names := make(map[string]int)
			for k, v := range tt.seed {
				names[k] = v
			}

			pkt2, start := dns.BuildNameCompressed(pkt, tt.input, names)
			if start < 0 || start >= len(pkt2) {
				t.Fatalf("bad start offset: %d len=%d", start, len(pkt2))
			}

			h := fmt.Sprintf("% X", pkt2)
			if !strings.Contains(h, strings.ToUpper(tt.wantHexHas)) {
				t.Fatalf("wire mismatch:\n got: %s\nwant contains: %s", h, tt.wantHexHas)
			}

			if tt.wantEnd && pkt2[len(pkt2)-1] != 0x00 {
				t.Fatalf("expected trailing 00 terminator")
			}
			if !tt.wantEnd && pkt2[len(pkt2)-1] == 0x00 {
				t.Fatalf("did not expect trailing 00 before pointer")
			}

			// Offsets recorded at length bytes
			if _, ok := names[tt.input]; !ok {
				t.Fatalf("full name offset not recorded")
			}
			// For the compressed case, unmatched prefix suffixes should be recorded.
			if strings.HasPrefix(tt.name, "compressed") {
				if _, ok := names["mail.google.com"]; !ok {
					t.Fatalf("suffix offset for 'mail.google.com' not recorded")
				}
			}
		})
	}
}
