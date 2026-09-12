package krb5

import "testing"

// Every one of these takes bytes straight off the network. One panic was
// already found here — gokrb5's DecryptMessage slices off a checksum without
// checking there is one — so the question is asked of each entry point rather
// than of the one that happened to fail.
func TestNoEntryPointPanicsOnShortInput(t *testing.T) {
	c := testContext(t)
	sealed, err := c.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := c.Wrap([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	mic, err := c.MIC([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	apReq := []byte{0x60, 0x82, 0x02, 0xf0, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86}

	for _, tc := range []struct {
		name string
		full []byte
		call func([]byte)
	}{
		{"Unseal", sealed, func(b []byte) { c.Unseal(b) }},
		{"Unwrap", wrapped, func(b []byte) { c.Unwrap(b) }},
		{"VerifyMIC", mic, func(b []byte) { c.VerifyMIC([]byte("hello"), b) }},
		{"Accept", apReq, func(b []byte) { (&Acceptor{}).Accept(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for n := range len(tc.full) + 1 {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%d bytes panicked: %v", n, r)
						}
					}()
					tc.call(tc.full[:n])
				}()
			}
		})
	}
}

// And on bytes that are the right LENGTH and the wrong content: a length
// check is not a parse.
func TestNoEntryPointPanicsOnGarbage(t *testing.T) {
	c := testContext(t)
	sealed, _ := c.Seal([]byte("hello"))
	garbage := make([]byte, len(sealed))
	for i := range garbage {
		garbage[i] = byte(i * 7)
	}
	for _, tc := range []struct {
		name string
		call func([]byte)
	}{
		{"Unseal", func(b []byte) { c.Unseal(b) }},
		{"Unwrap", func(b []byte) { c.Unwrap(b) }},
		{"VerifyMIC", func(b []byte) { c.VerifyMIC(nil, b) }},
		{"Accept", func(b []byte) { (&Acceptor{}).Accept(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on garbage: %v", r)
				}
			}()
			tc.call(garbage)
			// A wrap token id in front of garbage exercises the parse that
			// follows rather than the id check that precedes it.
			garbage[0], garbage[1] = 0x05, 0x04
			tc.call(garbage)
			garbage[0], garbage[1] = 0x04, 0x04
			tc.call(garbage)
		})
	}
}
