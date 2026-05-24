package dat

import (
	"strconv"
	"strings"
)

type Certificate struct {
	Cid           uint64
	cidPreCopy    string
	SignatureKey  *DatSignature
	CryptoKey     *DatCrypto
	DatIssueBegin uint64
	DatIssueEnd   uint64
	DatTTL        uint64
}

func NewCertificate(cid uint64, issuedAt, issuanceDuration, ttl uint64, signatureKey *DatSignature, cryptoKey *DatCrypto) (*Certificate, error) {
	if ttl == 0 {
		return nil, ErrInvalidDatTtl
	}
	if issuanceDuration < ttl*2 && issuanceDuration < (ttl+3600) {
		return nil, ErrInvalidIssuanceDuration
	}

	cidPreCopy := "." + ToHexFromU64(cid) + "."

	return &Certificate{
		Cid:           cid,
		cidPreCopy:    cidPreCopy,
		SignatureKey:  signatureKey,
		CryptoKey:     cryptoKey,
		DatIssueBegin: issuedAt,
		DatIssueEnd:   issuedAt + issuanceDuration,
		DatTTL:        ttl,
	}, nil
}

func GenerateCertificate(cid uint64, issuedAt, issuanceDuration, ttl uint64, signatureAlgorithm DatSignatureAlgorithm, cryptoAlgorithm DatCryptoAlgorithm) (*Certificate, error) {
	sk, err := GenerateSignatureKey(signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	ck := GenerateCryptoKey(cryptoAlgorithm)
	return NewCertificate(cid, issuedAt, issuanceDuration, ttl, sk, ck)
}

func (c *Certificate) Expired() bool {
	return (c.DatIssueEnd + c.DatTTL) < NowUnixTimestamp()
}

func (c *Certificate) Issuable() bool {
	now := NowUnixTimestamp()
	return c.Signable() && now >= c.DatIssueBegin && now <= c.DatIssueEnd
}

func (c *Certificate) Signable() bool {
	return c.SignatureKey.Signable()
}

func (c *Certificate) SignatureAlgorithm() DatSignatureAlgorithm {
	return c.SignatureKey.Algorithm()
}

func (c *Certificate) CryptoAlgorithm() DatCryptoAlgorithm {
	return c.CryptoKey.Algorithm()
}

func (c *Certificate) Export(verifyOnly bool) (string, error) {
	var sb strings.Builder
	sb.WriteString(ToHexFromU64(c.Cid))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatIssueBegin, 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatIssueEnd-c.DatIssueBegin, 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatTTL, 10))
	sb.WriteString(".")
	sb.WriteString(string(c.SignatureKey.Algorithm()))
	sb.WriteString(".")
	sb.WriteString(string(c.CryptoKey.Algorithm()))
	sb.WriteString(".")

	key, err := c.SignatureKey.ExportKeyOption(verifyOnly || !c.Signable())
	if err != nil {
		return "", err
	}

	sb.WriteString(EncodeBase64URL(key))
	sb.WriteString(".")
	sb.WriteString(EncodeBase64URL(c.CryptoKey.ToBytes()))

	return sb.String(), nil
}

func ParseCertificate(format string) (*Certificate, error) {
	parts := strings.Split(format, ".")
	if len(parts) != 8 {
		return nil, ErrInvalidCertificateFormat
	}

	cid, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return nil, ErrInvalidDat
	}

	issuedAt, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}

	issuanceDuration, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}

	ttl, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}

	sigAlgo := DatSignatureAlgorithm(parts[4])
	sigKeyBytes, err := DecodeBase64URL(parts[6])
	if err != nil {
		return nil, err
	}

	signatureKey, err := NewSignatureKey(sigAlgo, sigKeyBytes, nil)
	if err != nil {
		// Try treating as public key if it failed?
		signatureKey, err = NewSignatureKey(sigAlgo, nil, sigKeyBytes)
		if err != nil {
			return nil, err
		}
	}

	cryptoAlgo := DatCryptoAlgorithm(parts[5])
	cryptoKeyBytes, err := DecodeBase64URL(parts[7])
	if err != nil {
		return nil, err
	}
	cryptoKey, err := NewCryptoKey(cryptoAlgo, cryptoKeyBytes)
	if err != nil {
		return nil, err
	}

	return NewCertificate(cid, issuedAt, issuanceDuration, ttl, signatureKey, cryptoKey)
}
