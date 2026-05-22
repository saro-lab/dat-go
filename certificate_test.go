package dat_test

import (
	"dat"
	"fmt"
	"math/rand/v2"
	"testing"
)

func randStringCert() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 100)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

func unitCert(t *testing.T, failCertificate *dat.Certificate, cid uint64, signatureAlgorithm dat.SignatureAlgorithm, cryptoAlgorithm dat.CryptoAlgorithm, plain string, secure string) error {
	tag := fmt.Sprintf("dat.%s.%s.%x", signatureAlgorithm, cryptoAlgorithm, cid)

	now := dat.NowUnixTimestamp()
	newCertificate, err := dat.GenerateCertificate(cid, signatureAlgorithm, cryptoAlgorithm, now-10, now+600, 60)
	if err != nil {
		return err
	}
	newCertificateStr, err := newCertificate.Export(dat.Signing)
	if err != nil {
		return err
	}

	readCertificate, err := dat.ParseCertificate(newCertificateStr)
	if err != nil {
		return err
	}

	manager := dat.NewManager()
	token, err := manager.IssueWithCertificate(newCertificate, plain, secure)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", tag, token)

	d, err := dat.ParseDat(token)
	if err != nil {
		return err
	}

	payload, err := manager.ParseWithCertificate(readCertificate, d)
	if err != nil {
		return err
	}
	sp, _ := payload.ToStringPayload()
	fmt.Printf("%s:%s\n", tag, sp.String())

	if plain != sp.Plain {
		t.Errorf("expected plain %s, got %s", plain, sp.Plain)
	}
	if secure != sp.Secure {
		t.Errorf("expected secure %s, got %s", secure, sp.Secure)
	}

	if _, err := manager.ParseWithCertificate(failCertificate, d); err == nil {
		t.Errorf("should fail with different certificate")
	}

	return nil
}

func TestCertificate(t *testing.T) {
	signAlgs := []dat.SignatureAlgorithm{dat.P256, dat.P384, dat.P521}
	cryptoAlgs := []dat.CryptoAlgorithm{dat.AES128GCMN, dat.AES256GCMN}

	now := dat.NowUnixTimestamp()
	failCertificate, _ := dat.GenerateCertificate(192874, dat.P256, dat.AES256GCMN, now-10, now+600, 60)

	for _, signAlg := range signAlgs {
		for _, cryptoAlg := range cryptoAlgs {
			// random
			for i := uint64(1); i < 21; i++ {
				plain := randStringCert()
				secure := randStringCert()
				if err := unitCert(t, failCertificate, i, signAlg, cryptoAlg, plain, secure); err != nil {
					t.Fatalf("@%v", err)
				}
			}
			// empty
			if err := unitCert(t, failCertificate, 0, signAlg, cryptoAlg, "", ""); err != nil {
				t.Fatal(err)
			}
		}
	}
}
