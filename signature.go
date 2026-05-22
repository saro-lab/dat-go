package dat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
)

type SignatureAlgorithm string

const (
	P256 SignatureAlgorithm = "P256"
	P384 SignatureAlgorithm = "P384"
	P521 SignatureAlgorithm = "P521"
)

type SignatureKeyExportOption string

const (
	Pair      SignatureKeyExportOption = "PAIR"
	Signing   SignatureKeyExportOption = "SIGNING"
	Verifying SignatureKeyExportOption = "VERIFYING"
)

type SignatureKey struct {
	algorithm    SignatureAlgorithm
	privateKey   *ecdsa.PrivateKey
	publicKey    *ecdsa.PublicKey
	privateBytes []byte
	publicBytes  []byte
}

func NewSignatureKey(algorithm SignatureAlgorithm, privateBytes, publicBytes []byte) (*SignatureKey, error) {
	var curve elliptic.Curve
	switch algorithm {
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	}

	sk := &SignatureKey{
		algorithm:    algorithm,
		privateBytes: privateBytes,
		publicBytes:  publicBytes,
	}

	if len(publicBytes) > 0 {
		x, y := elliptic.Unmarshal(curve, publicBytes)
		if x == nil {
			return nil, ErrInvalidSignatureKey
		}
		sk.publicKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}

	if len(privateBytes) > 0 {
		d := new(big.Int).SetBytes(privateBytes)
		if sk.publicKey == nil {
			x, y := curve.ScalarBaseMult(privateBytes)
			sk.publicKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
			sk.publicBytes = elliptic.MarshalCompressed(curve, x, y)
		}
		sk.privateKey = &ecdsa.PrivateKey{
			PublicKey: *sk.publicKey,
			D:         d,
		}
	}

	if sk.publicKey == nil && sk.privateKey == nil {
		return nil, ErrInvalidSignatureKey
	}

	return sk, nil
}

func GenerateSignatureKey(algorithm SignatureAlgorithm) (*SignatureKey, error) {
	var curve elliptic.Curve
	switch algorithm {
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, ErrGenerateSigningKeyError
	}

	byteSize := (curve.Params().BitSize + 7) / 8
	privateBytes := priv.D.FillBytes(make([]byte, byteSize))
	publicBytes := elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y)

	return &SignatureKey{
		algorithm:    algorithm,
		privateKey:   priv,
		publicKey:    &priv.PublicKey,
		privateBytes: privateBytes,
		publicBytes:  publicBytes,
	}, nil
}

func (sk *SignatureKey) Algorithm() SignatureAlgorithm {
	return sk.algorithm
}

func (sk *SignatureKey) SignatureSize() int {
	switch sk.algorithm {
	case P256:
		return 64
	case P384:
		return 96
	case P521:
		return 132
	default:
		return 0
	}
}

func (sk *SignatureKey) ToBytes() ([]byte, []byte) {
	return sk.privateBytes, sk.publicBytes
}

func (sk *SignatureKey) Sign(data []byte) ([]byte, error) {
	if sk.privateKey == nil {
		return nil, ErrVerifyOnlyCertificate
	}

	var h hash.Hash
	switch sk.algorithm {
	case P256:
		h = sha256.New()
	case P384:
		h = sha512.New384()
	case P521:
		h = sha512.New()
	}
	h.Write(data)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, sk.privateKey, digest)
	if err != nil {
		return nil, ErrSignError
	}

	byteSize := (sk.privateKey.Curve.Params().BitSize + 7) / 8
	// P521 signature size is 132 (66 + 66)
	sig := make([]byte, byteSize*2)
	r.FillBytes(sig[:byteSize])
	s.FillBytes(sig[byteSize:])

	return sig, nil
}

func (sk *SignatureKey) Verify(body, sign []byte) error {
	if sk.publicKey == nil {
		return ErrInvalidDat
	}

	byteSize := (sk.publicKey.Curve.Params().BitSize + 7) / 8
	if len(sign) != byteSize*2 {
		return ErrInvalidDat
	}

	r := new(big.Int).SetBytes(sign[:byteSize])
	s := new(big.Int).SetBytes(sign[byteSize:])

	var h hash.Hash
	switch sk.algorithm {
	case P256:
		h = sha256.New()
	case P384:
		h = sha512.New384()
	case P521:
		h = sha512.New()
	}
	h.Write(body)
	digest := h.Sum(nil)

	if ecdsa.Verify(sk.publicKey, digest, r, s) {
		return nil
	}
	return ErrInvalidDat
}

func (sk *SignatureKey) HasSigningKey() bool {
	return sk.privateKey != nil
}
