package krb5

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/types"
)

// checkCipher refuses an EncryptedData whose cipher is too short to be one.
//
// ⛔ This is not belt and braces. gokrb5's DecryptMessage slices a checksum
// off the end and a confounder off the front without checking either is
// there, so a cipher of three bytes PANICS — before any key is checked, from
// an unauthenticated caller. Truncating a valid token does not find it: the
// ASN.1 parse refuses those long before the decryption. It takes a token that
// is well-formed all the way down and simply lies about a length.
//
// A fix is submitted upstream (jcmturner/gokrb5#580). This stays until it is
// released and the version here is raised: an open pull request is not a
// fixed dependency, and the last merge in that repository was in 2023.
func checkCipher(what string, ed types.EncryptedData) error {
	et, err := crypto.GetEtype(ed.EType)
	if err != nil {
		// An encryption type this build cannot do. Refusing by name beats
		// letting the decryption fail somewhere less legible.
		return fmt.Errorf("%w: %s uses encryption type %d: %w", ErrRejected, what, ed.EType, err)
	}
	if min := et.GetConfounderByteSize() + et.GetHMACBitLength()/8; len(ed.Cipher) < min {
		return fmt.Errorf("%w: %s carries %d cipher bytes, fewer than the %d a message of type %d needs",
			ErrRejected, what, len(ed.Cipher), min, ed.EType)
	}
	return nil
}
