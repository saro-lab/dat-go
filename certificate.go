package dat

import (
	"strconv"
	"strings"
)

type Certificate struct {
	Cid           uint64
	cidPreCopy    string
	SignatureKey  *SignatureKey
	CryptoKey     *CryptoKey
	DatIssueBegin uint64
	DatIssueEnd   uint64
	DatTTL        uint64
}

func NewCertificate(cid uint64, signatureKey *SignatureKey, cryptoKey *CryptoKey, issueBegin, issueEnd, ttl uint64) (*Certificate, error) {
	cidPreCopy := "." + ToHexFromU64(cid) + "."

	return &Certificate{
		Cid:           cid,
		cidPreCopy:    cidPreCopy,
		SignatureKey:  signatureKey,
		CryptoKey:     cryptoKey,
		DatIssueBegin: issueBegin,
		DatIssueEnd:   issueEnd,
		DatTTL:        ttl,
	}, nil
}

func GenerateCertificate(cid uint64, signatureAlgorithm SignatureAlgorithm, cryptoAlgorithm CryptoAlgorithm, issueBegin, issueEnd, ttl uint64) (*Certificate, error) {
	sk, err := GenerateSignatureKey(signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	ck := GenerateCryptoKey(cryptoAlgorithm)
	return NewCertificate(cid, sk, ck, issueBegin, issueEnd, ttl)
}

func (c *Certificate) Expired() bool {
	return (c.DatIssueEnd + c.DatTTL) < NowUnixTimestamp()
}

func (c *Certificate) Issuable() bool {
	now := NowUnixTimestamp()
	return c.HasSigningKey() && now >= c.DatIssueBegin && now <= c.DatIssueEnd
}

func (c *Certificate) HasSigningKey() bool {
	return c.SignatureKey.HasSigningKey()
}

func (c *Certificate) SignatureAlgorithm() SignatureAlgorithm {
	return c.SignatureKey.Algorithm()
}

func (c *Certificate) CryptoAlgorithm() CryptoAlgorithm {
	return c.CryptoKey.Algorithm()
}

func (c *Certificate) Export(option SignatureKeyExportOption) (string, error) {
	var sb strings.Builder
	sb.WriteString(ToHexFromU64(c.Cid))
	sb.WriteString(".")
	sb.WriteString(string(c.SignatureKey.Algorithm()))
	sb.WriteString(".")

	sk, vk := c.SignatureKey.ToBytes()
	if len(sk) == 0 && option != Verifying {
		return "", ErrVerifyOnlyCertificate
	}

	switch option {
	case Pair:
		sb.WriteString(EncodeBase64URL(sk))
		sb.WriteString("~")
		sb.WriteString(EncodeBase64URL(vk))
	case Signing:
		sb.WriteString(EncodeBase64URL(sk))
	case Verifying:
		sb.WriteString("~")
		sb.WriteString(EncodeBase64URL(vk))
	}

	sb.WriteString(".")
	sb.WriteString(string(c.CryptoKey.Algorithm()))
	sb.WriteString(".")
	sb.WriteString(EncodeBase64URL(c.CryptoKey.ToBytes()))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatIssueBegin, 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatIssueEnd, 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatUint(c.DatTTL, 10))

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

	sigAlgo := SignatureAlgorithm(parts[1])
	sigKeyStr := parts[2]
	var skBytes, vkBytes []byte
	if strings.Contains(sigKeyStr, "~") {
		subParts := strings.Split(sigKeyStr, "~")
		if subParts[0] == "" {
			vkBytes, err = DecodeBase64URL(subParts[1])
		} else {
			skBytes, err = DecodeBase64URL(subParts[0])
			if err == nil {
				vkBytes, err = DecodeBase64URL(subParts[1])
			}
		}
	} else {
		skBytes, err = DecodeBase64URL(sigKeyStr)
	}
	if err != nil {
		return nil, err
	}

	signatureKey, err := NewSignatureKey(sigAlgo, skBytes, vkBytes)
	if err != nil {
		return nil, err
	}

	cryptoAlgo := CryptoAlgorithm(parts[3])
	cryptoKeyBytes, err := DecodeBase64URL(parts[4])
	if err != nil {
		return nil, err
	}
	cryptoKey, err := NewCryptoKey(cryptoAlgo, cryptoKeyBytes)
	if err != nil {
		return nil, err
	}

	issueBegin, err := strconv.ParseUint(parts[5], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}
	issueEnd, err := strconv.ParseUint(parts[6], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}
	ttl, err := strconv.ParseUint(parts[7], 10, 64)
	if err != nil {
		return nil, ErrInvalidCertificateFormat
	}

	return NewCertificate(cid, signatureKey, cryptoKey, issueBegin, issueEnd, ttl)
}
