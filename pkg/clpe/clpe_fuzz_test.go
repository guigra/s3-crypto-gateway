package clpe

import "testing"

func FuzzDecryptNeverPanics(f *testing.F) {
	valid, err := Encrypt([]byte("secreto"), "tenant-a", kObj, fixedKek)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(nil))
	f.Add([]byte("CLPE"))
	f.Add(valid)

	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decrypt(input, kObj, fixedKek)
	})
}
