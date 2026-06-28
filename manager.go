package dat

import (
	"slices"
	"strconv"
	"strings"
	"sync"
)

type Manager struct {
	issuer       *Certificate
	certificates []*Certificate
	mu           sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		certificates: []*Certificate{},
	}
}

func (m *Manager) Issue(plain, secure string) (string, error) {
	m.mu.RLock()
	issuer := m.issuer
	m.mu.RUnlock()

	if issuer == nil {
		return "", ErrSigningKeyNotExists
	}
	return m.IssueWithCertificate(issuer, plain, secure)
}

func (m *Manager) Parse(datStr string) (Payload, error) {
	d, err := ParseDat(datStr)
	if err != nil {
		return Payload{}, err
	}
	return m.ParseDat(d)
}

func (m *Manager) ParseDat(dat *Dat) (Payload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cert := range m.certificates {
		if cert.Cid == dat.Cid {
			return m.ParseWithCertificate(cert, dat)
		}
	}
	return Payload{}, ErrCidNotFound
}

func (m *Manager) ParseWithoutVerify(datStr string) (Payload, error) {
	d, err := ParseDat(datStr)
	if err != nil {
		return Payload{}, err
	}
	return m.ParseDatWithoutVerify(d)
}

func (m *Manager) ParseDatWithoutVerify(dat *Dat) (Payload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cert := range m.certificates {
		if cert.Cid == dat.Cid {
			return m.ParseWithoutVerifyWithCertificate(cert, dat)
		}
	}
	return Payload{}, ErrCidNotFound
}

func (m *Manager) ExportCids() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cids := make([]uint64, len(m.certificates))
	for i, cert := range m.certificates {
		cids[i] = cert.Cid
	}
	return cids
}

func (m *Manager) Export(verifyOnly bool) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder
	for i, cert := range m.certificates {
		if i > 0 {
			sb.WriteString("\n")
		}
		exported, _ := cert.Export(verifyOnly)
		sb.WriteString(exported)
	}
	return sb.String()
}

func (m *Manager) ExportCertificates() []*Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.certificates)
}

func (m *Manager) Import(format string, clear bool) (int, error) {
	lines := strings.Split(format, "\n")
	var newCerts []*Certificate
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cert, err := ParseCertificate(line)
		if err != nil {
			return 0, err
		}
		newCerts = append(newCerts, cert)
	}
	return m.ImportCertificates(newCerts, clear)
}

func (m *Manager) ImportCertificates(newCertificates []*Certificate, clear bool) (int, error) {
	ids := make(map[uint64]bool)
	for _, cert := range newCertificates {
		if ids[cert.Cid] {
			return 0, ErrDuplicatedCid
		}
		ids[cert.Cid] = true
	}

	var renewCount int = 0

	m.mu.Lock()
	defer m.mu.Unlock()

	var certificates []*Certificate
	if clear {
		certificates = []*Certificate{}
	} else {
		certificates = slices.Clone(m.certificates)
	}

	for _, newCert := range newCertificates {
		found := false
		for _, cert := range certificates {
			if cert.Cid == newCert.Cid {
				found = true
				break
			}
		}
		if !found {
			certificates = append(certificates, newCert)
			renewCount++
		}
	}

	var filtered []*Certificate
	for _, cert := range certificates {
		if !cert.Expired() {
			filtered = append(filtered, cert)
		}
	}

	slices.SortFunc(filtered, func(a, b *Certificate) int {
		if a.DatIssuanceEndSeconds < b.DatIssuanceEndSeconds {
			return -1
		} else if a.DatIssuanceEndSeconds > b.DatIssuanceEndSeconds {
			return 1
		}
		return 0
	})

	var issuer *Certificate
	for i := len(filtered) - 1; i >= 0; i-- {
		if filtered[i].Issuable() {
			issuer = filtered[i]
			break
		}
	}

	m.issuer = issuer
	m.certificates = filtered

	return renewCount, nil
}

func (m *Manager) IssueWithCertificate(certificate *Certificate, plain, secure string) (string, error) {
	expire := strconv.FormatUint(NowUnixTimestamp()+certificate.DatTtlSeconds, 10)

	var sb strings.Builder
	sb.WriteString(expire)
	sb.WriteString(certificate.cidPreCopy)
	sb.WriteString(EncodeBase64URL([]byte(plain)))
	sb.WriteString(".")

	encrypted, err := certificate.CryptoKey.Encrypt([]byte(secure))
	if err != nil {
		return "", err
	}
	sb.WriteString(EncodeBase64URL(encrypted))

	signature, err := certificate.SignatureKey.Sign([]byte(sb.String()))
	if err != nil {
		return "", err
	}
	sb.WriteString(".")
	sb.WriteString(EncodeBase64URL(signature))

	return sb.String(), nil
}

func (m *Manager) ParseWithCertificate(certificate *Certificate, dat *Dat) (Payload, error) {
	if err := certificate.SignatureKey.Verify(dat.BodyBytes(), dat.Signature); err != nil {
		return Payload{}, ErrInvalidDat
	}
	return m.ParseWithoutVerifyWithCertificate(certificate, dat)
}

func (m *Manager) ParseWithoutVerifyWithCertificate(certificate *Certificate, dat *Dat) (Payload, error) {
	plain, err := dat.Plain()
	if err != nil {
		return Payload{}, err
	}
	secureEncoded, err := dat.Secure()
	if err != nil {
		return Payload{}, err
	}
	secure, err := certificate.CryptoKey.Decrypt(secureEncoded)
	if err != nil {
		return Payload{}, err
	}

	return Payload{
		Plain:  plain,
		Secure: secure,
	}, nil
}
