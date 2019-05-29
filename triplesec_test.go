// The design and name of TripleSec is (C) Keybase 2013
// This Go implementation is (C) Filippo Valsorda 2014
// Use of this source code is governed by the MIT License

package triplesec

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func functionThatPrintsUglyWarnings() {}

func isProduction() bool {
	return false
}

func testCycle(t *testing.T, version Version) {
	plaintext := []byte("1234567890-")
	password := []byte("42")

	c, err := NewCipher(password, nil, version, functionThatPrintsUglyWarnings, isProduction)
	if err != nil {
		t.Fatal(err)
	}

	origPlaintext := append([]byte{}, plaintext...)
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	origCiphertext := append([]byte{}, ciphertext...)
	newPlaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(newPlaintext, plaintext) {
		t.Error("newPlaintext != plaintext")
	}
	if !bytes.Equal(origPlaintext, plaintext) {
		t.Error("origPlaintext != plaintext")
	}
	if !bytes.Equal(origCiphertext, ciphertext) {
		t.Error("origCiphertext != ciphertext")
	}
	if !bytes.Equal(password, []byte("42")) {
		t.Error("password changed")
	}
}

func TestCycle(t *testing.T) {
	for version := range versionParamsLookup {
		testCycle(t, version)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	plaintext := []byte("1234567890-")
	password := []byte("42")

	c, err := NewCipher(password, nil, Version(3), functionThatPrintsUglyWarnings, isProduction)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := c.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plaintext := []byte("1234567890-")
	password := []byte("42")

	c, err := NewCipher(password, nil, Version(3), functionThatPrintsUglyWarnings, isProduction)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = c.Decrypt(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func testBiggerBufSizes(t *testing.T, version Version) {
	// TODO: should we resize the buffers when we are passed smaller ones?

	plaintext := []byte("1234567890-")
	password := []byte("42")

	c, err := NewCipher(password, nil, version, functionThatPrintsUglyWarnings, isProduction)
	if err != nil {
		t.Fatal(err)
	}

	origPlaintext := append([]byte{}, plaintext...)
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	origCiphertext := append([]byte{}, ciphertext...)
	newPlaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(newPlaintext[:len(plaintext)], plaintext) {
		t.Error("newPlaintext != plaintext")
	}
	if !bytes.Equal(origPlaintext, plaintext) {
		t.Error("origPlaintext != plaintext")
	}
	if !bytes.Equal(origCiphertext, ciphertext) {
		t.Error("origCiphertext != ciphertext")
	}
	if !bytes.Equal(password, []byte("42")) {
		t.Error("password changed")
	}
}

func TestBiggerBufSizes(t *testing.T) {
	for version := range versionParamsLookup {
		testBiggerBufSizes(t, version)
	}
}

func testSmallerBufSizes(t *testing.T, version Version) {
	plaintext := []byte("1234567890-")
	password := []byte("42")

	c, err := NewCipher(password, nil, version, functionThatPrintsUglyWarnings, isProduction)
	if err != nil {
		t.Fatal(err)
	}

	origPlaintext := append([]byte{}, plaintext...)
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	origCiphertext := append([]byte{}, ciphertext...)
	newPlaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(newPlaintext, plaintext) {
		t.Error("newPlaintext != plaintext")
	}
	if !bytes.Equal(origPlaintext, plaintext) {
		t.Error("origPlaintext != plaintext")
	}
	if !bytes.Equal(origCiphertext, ciphertext) {
		t.Error("origCiphertext != ciphertext")
	}
	if !bytes.Equal(password, []byte("42")) {
		t.Error("password changed")
	}
}

func TestSmallerBufSizes(t *testing.T) {
	for version := range versionParamsLookup {
		testSmallerBufSizes(t, version)
	}
}

func TestBadPwV3(t *testing.T) {
	ciphertext, _ := hex.DecodeString("1c94d7de0000000359a5e5d60f09ebb6bc3fdab6642725e03bc3d51e167fa60327df567476d467f8b6ce65a909b4f582443f230ff10a36f60315ebce1cf1395d7b763c768764207f4f4cc5207a21272f3a5542f35db73c94fbc7bd551d4d6b0733e0b27fdf9606b8a26d45c4b79818791b6ae1ad34c23e58de482d454895618a1528ec722c5218650f8a2f55f63a6066ccf875f46c9b68ed31bc1ddce8881d704be597e1b5006d16ebe091a02e24d569f3d09b0578d12f955543e1a1f1dd75784b8b4cba7ca0bb7044389eb6354cea628a21538d")
	c, _ := NewCipher([]byte("423"), nil, Version(3), functionThatPrintsUglyWarnings, isProduction)
	_, err := c.Decrypt(ciphertext)
	if err == nil {
		t.Error("needed an error on bad PW")
	} else if _, ok := err.(BadPassphraseError); !ok {
		t.Error("got wrong type of error")
	}
}

func TestBadPwV4(t *testing.T) {
	ciphertext, _ := hex.DecodeString("1c94d7de00000004ab62712b6a43fba017a7a13333b59d3650365fcebded3bd64741a99b2070fa12e4145766afa1b2dbcaca4d2053963f441be82963046766f16a4f82186a9ba7a7cf04f19da9a695a4a7ae9f6036a5d3b456ad97d512af55e61245c9a096db8a4b73cc64491ec67e5381ec14f2ce6f3db922b5cec7cea86305681a0204d6fb9522e7ec8851f8d85c4e4319473c2899ece487324093f144d27ea13355fd9a03a0765afc5f5750152824c6632dfd50bd25ac340aaa6e6cd3664c21d4501ef8b3107c3fa62b9a97d79a9ccc64")
	c, _ := NewCipher([]byte("wrong password"), nil, Version(4), functionThatPrintsUglyWarnings, isProduction)
	_, err := c.Decrypt(ciphertext)
	if err == nil {
		t.Error("needed an error on bad PW")
	} else if _, ok := err.(BadPassphraseError); !ok {
		t.Error("got wrong type of error")
	}
}

func TestRandomness(t *testing.T) {
	for _, version := range []Version{3, 4} {
		key := []byte("YELLOW_SUBMARINE")
		cipher, _ := NewCipher(key, nil, version, functionThatPrintsUglyWarnings, isProduction)
		pt := []byte("foobar")
		once, _ := cipher.Encrypt(pt)
		twice, _ := cipher.Encrypt(pt)
		onceHex := hex.EncodeToString(once)
		twiceHex := hex.EncodeToString(twice)
		if onceHex == twiceHex {
			t.Errorf("got same encryption twice in a row")
		}
		cipher, _ = NewCipher(key, nil, version, functionThatPrintsUglyWarnings, isProduction)
		thrice, _ := cipher.Encrypt(pt)
		thriceHex := hex.EncodeToString(thrice)
		if onceHex == thriceHex || twiceHex == thriceHex {
			t.Errorf("got same encryption twice after making cipher again")
		}
	}
}
