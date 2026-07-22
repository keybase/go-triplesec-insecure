package triplesec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func newRobustnessTestCipher(t *testing.T, passphrase, salt []byte, version Version) *Cipher {
	t.Helper()
	cipher, err := NewCipher(passphrase, salt, version, functionThatPrintsUglyWarnings, isProduction)
	require.NoError(t, err)
	return cipher
}

func TestDecryptRejectsEveryTruncatedCiphertextLength(t *testing.T) {
	for _, version := range []Version{3, 4} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			cipher := newRobustnessTestCipher(t, []byte("password"), nil, version)
			header := make([]byte, len(MagicBytes)+VersionBytesLen)
			copy(header, MagicBytes[:])
			binary.BigEndian.PutUint32(header[len(MagicBytes):], uint32(version))
			versionParams := versionParamsLookup[version]

			for length := 0; length < versionParams.Overhead(); length++ {
				input := make([]byte, length)
				copy(input, header)
				_, err := cipher.Decrypt(input)
				require.Error(t, err, "length %d", length)
			}
		})
	}
}

func TestSaltChangesInvalidateDerivedKeyCache(t *testing.T) {
	passphrase := []byte("password")
	plaintext := []byte("message")
	salt1 := bytes.Repeat([]byte{0x01}, SaltLen)
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)

	producer1 := newRobustnessTestCipher(t, passphrase, salt1, 4)
	ciphertext1, err := producer1.Encrypt(plaintext)
	require.NoError(t, err)
	producer2 := newRobustnessTestCipher(t, passphrase, salt2, 4)
	ciphertext2, err := producer2.Encrypt(plaintext)
	require.NoError(t, err)

	consumer := newRobustnessTestCipher(t, passphrase, nil, 4)
	result, err := consumer.Decrypt(ciphertext1)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
	result, err = consumer.Decrypt(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

func TestCrossVersionDecryption(t *testing.T) {
	passphrase := []byte("password")
	plaintext := []byte("cross-version message")

	producers := []struct {
		version  Version
		saltByte byte
	}{
		{version: 3, saltByte: 3},
		{version: 4, saltByte: 4},
	}
	for _, producerParams := range producers {
		producerVersion := producerParams.version
		producer := newRobustnessTestCipher(t, passphrase, bytes.Repeat([]byte{producerParams.saltByte}, SaltLen), producerVersion)
		ciphertext, err := producer.Encrypt(plaintext)
		require.NoError(t, err)

		for _, consumerVersion := range []Version{3, 4} {
			t.Run(fmt.Sprintf("v%d_with_v%d_cipher", producerVersion, consumerVersion), func(t *testing.T) {
				consumer := newRobustnessTestCipher(t, passphrase, nil, consumerVersion)
				result, err := consumer.Decrypt(ciphertext)
				require.NoError(t, err)
				require.Equal(t, plaintext, result)
			})
		}
	}
}

func TestCipherOwnsPassphraseAndSalt(t *testing.T) {
	passphrase := []byte("password")
	originalPassphrase := bytes.Clone(passphrase)
	salt := bytes.Repeat([]byte{0x03}, SaltLen)
	originalSalt := bytes.Clone(salt)
	cipher := newRobustnessTestCipher(t, passphrase, salt, 4)

	scrub(passphrase)
	scrub(salt)
	ciphertext, err := cipher.Encrypt([]byte("message"))
	require.NoError(t, err)
	require.Equal(t, originalSalt, ciphertext[len(MagicBytes)+VersionBytesLen:len(MagicBytes)+VersionBytesLen+SaltLen])

	consumer := newRobustnessTestCipher(t, originalPassphrase, nil, 4)
	_, err = consumer.Decrypt(ciphertext)
	require.NoError(t, err)

	exposedSalt, err := cipher.GetSalt()
	require.NoError(t, err)
	scrub(exposedSalt)
	require.Equal(t, originalSalt, cipher.salt)

	callerPassphrase := []byte("caller-owned password")
	scrubCipher := newRobustnessTestCipher(t, callerPassphrase, nil, 4)
	scrubCipher.Scrub()
	require.Equal(t, []byte("caller-owned password"), callerPassphrase)
}

func TestDecryptDoesNotRetainCiphertextSalt(t *testing.T) {
	passphrase := []byte("password")
	salt := bytes.Repeat([]byte{0x04}, SaltLen)
	producer := newRobustnessTestCipher(t, passphrase, salt, 4)
	ciphertext, err := producer.Encrypt([]byte("message"))
	require.NoError(t, err)

	consumer := newRobustnessTestCipher(t, passphrase, nil, 4)
	_, err = consumer.Decrypt(ciphertext)
	require.NoError(t, err)

	headerLen := len(MagicBytes) + VersionBytesLen
	scrub(ciphertext[headerLen : headerLen+SaltLen])
	require.Equal(t, salt, consumer.salt)
}

func TestDeriveKeyExtraBoundsAndCachedLength(t *testing.T) {
	cipher := newRobustnessTestCipher(t, []byte("password"), bytes.Repeat([]byte{0x05}, SaltLen), 4)

	_, extra, err := cipher.DeriveKey(32)
	require.NoError(t, err)
	require.Len(t, extra, 32)
	_, extra, err = cipher.DeriveKey(10)
	require.NoError(t, err)
	require.Len(t, extra, 10)
	_, extra, err = cipher.DeriveKey(MaxDeriveKeyExtra)
	require.NoError(t, err)
	require.Len(t, extra, MaxDeriveKeyExtra)

	_, _, err = cipher.DeriveKey(-1)
	require.Error(t, err)
	_, _, err = cipher.DeriveKey(MaxDeriveKeyExtra + 1)
	require.Error(t, err)
}

func FuzzDecryptDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(MagicBytes[:])
	f.Add(append(MagicBytes[:], 0, 0, 0, 4))

	f.Fuzz(func(t *testing.T, input []byte) {
		cipher := newRobustnessTestCipher(t, []byte("password"), nil, 4)
		_, _ = cipher.Decrypt(input)
	})
}
