package dat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type DatCryptoAlgorithm string

const (
	IvAes128Gcm DatCryptoAlgorithm = "IV-AES128-GCM"
	IvAes256Gcm DatCryptoAlgorithm = "IV-AES256-GCM"
)

// Deprecated: Use IvAes128Gcm, IvAes256Gcm instead
const (
	AES128GCMN = IvAes128Gcm
	AES256GCMN = IvAes256Gcm
)

type DatCrypto struct {
	algorithm DatCryptoAlgorithm
	key       []byte
	block     cipher.Block
	gcm       cipher.AEAD
}

func NewCryptoKey(algorithm DatCryptoAlgorithm, data []byte) (*DatCrypto, error) {
	block, err := aes.NewCipher(data)
	if err != nil {
		return nil, ErrInvalidCryptoKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidCryptoKey
	}
	return &DatCrypto{
		algorithm: algorithm,
		key:       data,
		block:     block,
		gcm:       gcm,
	}, nil
}

func GenerateCryptoKey(algorithm DatCryptoAlgorithm) *DatCrypto {
	var size int
	switch algorithm {
	case IvAes128Gcm:
		size = 16
	case IvAes256Gcm:
		size = 32
	default:
		size = 32
	}
	key := make([]byte, size)
	_, _ = io.ReadFull(rand.Reader, key)
	ck, _ := NewCryptoKey(algorithm, key)
	return ck
}

func (ck *DatCrypto) Algorithm() DatCryptoAlgorithm {
	return ck.algorithm
}

func (ck *DatCrypto) ToBytes() []byte {
	return ck.key
}

func (ck *DatCrypto) KeyBase64Len() int {
	switch ck.algorithm {
	case IvAes128Gcm:
		return 22
	case IvAes256Gcm:
		return 43
	default:
		return 0
	}
}

func (ck *DatCrypto) Encrypt(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return []byte{}, nil
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrEncryptError
	}
	encData := make([]byte, 0, 12+len(body)+16)
	encData = append(encData, nonce...)
	encData = ck.gcm.Seal(encData, nonce, body, nil)
	return encData, nil
}

func (ck *DatCrypto) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if len(data) <= 12 {
		return nil, ErrDecryptError
	}
	nonce := data[:12]
	ciphertext := data[12:]
	plaintext, err := ck.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptError
	}
	return plaintext, nil
}
