package main

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

var (
	keyOnce sync.Once
	shared  [2]Keys
	keyErr  error
)

func testKeys(t *testing.T) (alice, bob *Keys) {
	t.Helper()
	keyOnce.Do(func() {
		for i := range shared {
			if shared[i], keyErr = NewKeys(); keyErr != nil {
				return
			}
		}
	})
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	return &shared[0], &shared[1]
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := randomBytes(t, keyLen)
	for _, n := range []int{0, 1, 15, 16, 17, 100, 4096} {
		plain := randomBytes(t, n)
		ct, err := Encrypt(key, plain)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if len(ct)%16 != 0 || len(ct) <= n {
			t.Errorf("len %d: unexpected ciphertext length %d", n, len(ct))
		}
		got, err := Decrypt(key, ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("len %d: round trip failed (err %v)", n, err)
		}
	}
}

func TestEncryptRejectsBadKeyLength(t *testing.T) {
	if _, err := Encrypt([]byte("short"), []byte("data")); err == nil {
		t.Error("expected an error for a 5-byte key")
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	key := randomBytes(t, keyLen)
	for _, data := range [][]byte{nil, {}, make([]byte, 15), make([]byte, 17)} {
		if _, err := Decrypt(key, data); err == nil {
			t.Errorf("expected an error for %d bytes of ciphertext", len(data))
		}
	}
}

func TestDecryptWithWrongKeyDoesNotRecoverPlaintext(t *testing.T) {
	plain := []byte("a message that spans more than one block of the cipher")
	ct, _ := Encrypt(randomBytes(t, keyLen), plain)
	got, err := Decrypt(randomBytes(t, keyLen), ct)
	if err == nil && bytes.Equal(got, plain) {
		t.Error("wrong key recovered the plaintext")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := randomBytes(t, 16)
	k1 := DeriveKey("password", salt)
	if len(k1) != keyLen {
		t.Fatalf("key length %d, want %d", len(k1), keyLen)
	}
	if !bytes.Equal(k1, DeriveKey("password", salt)) {
		t.Error("same password and salt gave different keys")
	}
	if bytes.Equal(k1, DeriveKey("Password", salt)) {
		t.Error("different passwords gave the same key")
	}
	if bytes.Equal(k1, DeriveKey("password", randomBytes(t, 16))) {
		t.Error("different salts gave the same key")
	}
}

func TestNewSalt(t *testing.T) {
	if got := len(NewSalt()); got != 16 {
		t.Errorf("salt length %d, want 16", got)
	}
}

func TestChecksum(t *testing.T) {
	for in, want := range map[string]string{
		"":    "d41d8cd98f00b204e9800998ecf8427e",
		"abc": "900150983cd24fb0d6963f7d28e17f72",
	} {
		if got := Checksum([]byte(in)); got != want {
			t.Errorf("Checksum(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a, b := []byte("one"), []byte("two")
	if got := Fingerprint(a, b); len(got) != 24 || got != Fingerprint(a, b) {
		t.Errorf("fingerprint %q is not a stable 24-character string", got)
	}
	if Fingerprint(a) == Fingerprint(b) {
		t.Error("different inputs gave the same fingerprint")
	}
}

func TestKeysSurviveStoringAndLoading(t *testing.T) {
	alice, _ := testKeys(t)
	loaded := Keys{RSAPrivate: alice.RSAPrivate, ECCPrivate: alice.ECCPrivate}
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	r1, e1 := alice.PublicKeys()
	r2, e2 := loaded.PublicKeys()
	if !bytes.Equal(r1, r2) || !bytes.Equal(e1, e2) {
		t.Error("loaded keys differ from the originals")
	}
}

func TestLoadRejectsBrokenKeys(t *testing.T) {
	alice, _ := testKeys(t)
	for name, k := range map[string]Keys{
		"empty":   {},
		"not pem": {RSAPrivate: "hello", ECCPrivate: alice.ECCPrivate},
		"bad ecc": {RSAPrivate: alice.RSAPrivate, ECCPrivate: []byte{1, 2, 3}},
	} {
		if err := k.Load(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSignVerify(t *testing.T) {
	alice, bob := testKeys(t)
	data := []byte("data to sign")
	sig, err := alice.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := alice.PublicKeys()
	if err := Verify(pub, data, sig); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	if Verify(pub, []byte("other data"), sig) == nil {
		t.Error("signature accepted for different data")
	}
	bad := append([]byte{}, sig...)
	bad[0] ^= 0xff
	if Verify(pub, data, bad) == nil {
		t.Error("corrupted signature accepted")
	}
	if bobPub, _ := bob.PublicKeys(); Verify(bobPub, data, sig) == nil {
		t.Error("signature accepted under another user's key")
	}
	if Verify([]byte("junk"), data, sig) == nil {
		t.Error("malformed public key accepted")
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	_, bob := testKeys(t)
	_, bobECC := bob.PublicKeys()
	fileKey := randomBytes(t, keyLen)

	eph, wrapped, err := WrapKey(bobECC, fileKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.UnwrapKey(eph, wrapped)
	if err != nil || !bytes.Equal(got, fileKey) {
		t.Fatalf("unwrap failed: %v", err)
	}
	eph2, _, _ := WrapKey(bobECC, fileKey)
	if bytes.Equal(eph, eph2) {
		t.Error("two wraps reused the same ephemeral key")
	}
}

func TestUnwrapKeyFailsForOtherRecipient(t *testing.T) {
	alice, bob := testKeys(t)
	_, bobECC := bob.PublicKeys()
	fileKey := randomBytes(t, keyLen)
	eph, wrapped, _ := WrapKey(bobECC, fileKey)

	got, err := alice.UnwrapKey(eph, wrapped)
	if err == nil && bytes.Equal(got, fileKey) {
		t.Error("another user unwrapped the file key")
	}
}

func TestWrapKeyRejectsBadRecipientKey(t *testing.T) {
	if _, _, err := WrapKey([]byte("not a point"), randomBytes(t, keyLen)); err == nil {
		t.Error("expected an error for a malformed recipient key")
	}
	alice, _ := testKeys(t)
	if _, err := alice.UnwrapKey([]byte("not a point"), make([]byte, 48)); err == nil {
		t.Error("expected an error for a malformed ephemeral key")
	}
}