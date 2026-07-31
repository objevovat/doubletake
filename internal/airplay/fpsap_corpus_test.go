package airplay

import (
	"crypto/sha256"
	"testing"
)

// fpsapCorpusPayloads builds a deterministic set of 128-byte challenge bodies:
// structural edge cases first -- block boundaries, single bits, all-ones with
// one byte cleared -- then a pseudorandom tail from the same xorshift generator
// TestFairPlaySAPHashCorpus uses.
func fpsapCorpusPayloads() [][128]byte {
	var out [][128]byte
	add := func(p [128]byte) { out = append(out, p) }

	var zero [128]byte
	add(zero)

	for _, v := range []byte{0x01, 0x42, 0x55, 0x7f, 0x80, 0xaa, 0xff} {
		var p [128]byte
		for i := range p {
			p[i] = v
		}
		add(p)
	}

	for _, s := range []byte{0x00, 0x40, 0x80, 0xc0} {
		var p [128]byte
		for i := range p {
			p[i] = s + byte(i)
		}
		add(p)
	}

	// One byte set, on and around every 16-byte block boundary.
	for _, idx := range []int{0, 1, 2, 15, 16, 31, 32, 63, 64, 95, 96, 126, 127} {
		for _, v := range []byte{0x01, 0x80, 0xff} {
			var p [128]byte
			p[idx] = v
			add(p)
		}
	}

	// One bit set in each of the eight blocks.
	for blk := 0; blk < 8; blk++ {
		for bit := 0; bit < 8; bit++ {
			var p [128]byte
			p[blk*16] = 1 << bit
			add(p)
		}
	}

	for _, idx := range []int{0, 63, 64, 127} {
		var p [128]byte
		for i := range p {
			p[i] = 0xff
		}
		p[idx] = 0
		add(p)
	}

	var state uint64 = 0x6a09e667f3bcc909
	for range 32 {
		var p [128]byte
		for i := range p {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			p[i] = byte(state)
		}
		add(p)
	}

	return out
}

// TestFPSAPExchangeCorpus widens the exchange coverage from the seven vectors in
// TestFPSAPExchangeGoldenVectors to 151.
//
// The expected aggregate was produced by a separate, independently derived
// implementation of this exchange, not by this package -- so it checks the two
// against each other rather than checking this package against itself.
func TestFPSAPExchangeCorpus(t *testing.T) {
	corpusHash := sha256.New()
	payloads := fpsapCorpusPayloads()
	for _, payload := range payloads {
		digest := fpsapExchangeForSAP(fpsapReferenceLocalSAP(), mustDecryptFPSAPBody(t, 3, payload))
		_, _ = corpusHash.Write(digest[:])
	}
	if len(payloads) != 151 {
		t.Fatalf("corpus length = %d, want 151", len(payloads))
	}
	requireFairPlayHex(t, "FPSAP exchange corpus", corpusHash.Sum(nil),
		"68f4a4d3ad5603fc569ee7deb013d3a5de91d7590274272a16750fe02370fd9d")
}
