package dat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type CryptoAlgorithm string

const (
	AES128GCMN CryptoAlgorithm = "AES128GCMN"
	AES256GCMN CryptoAlgorithm = "AES256GCMN"
)

type CryptoKey struct {
	algorithm CryptoAlgorithm
	key       []byte
	block     cipher.Block
	gcm       cipher.AEAD
}

func NewCryptoKey(algorithm CryptoAlgorithm, data []byte) (*CryptoKey, error) {
	block, err := aes.NewCipher(data)
	if err != nil {
		return nil, ErrInvalidCryptoKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidCryptoKey
	}
	return &CryptoKey{
		algorithm: algorithm,
		key:       data,
		block:     block,
		gcm:       gcm,
	}, nil
}

func GenerateCryptoKey(algorithm CryptoAlgorithm) *CryptoKey {
	var size int
	if algorithm == AES128GCMN {
		size = 16
	} else {
		size = 32
	}
	key := make([]byte, size)
	_, _ = io.ReadFull(rand.Reader, key)
	ck, _ := NewCryptoKey(algorithm, key)
	return ck
}

func (ck *CryptoKey) Algorithm() CryptoAlgorithm {
	return ck.algorithm
}

func (ck *CryptoKey) ToBytes() []byte {
	return ck.key
}

func (ck *CryptoKey) Encrypt(body []byte) ([]byte, error) {
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

func (ck *CryptoKey) Decrypt(data []byte) ([]byte, error) {
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
