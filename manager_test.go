package dat_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/saro-lab/dat-go"
)

func randString() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 100)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

func genCertificate(manager *dat.Manager) error {
	signAlgs := []dat.SignatureAlgorithm{dat.P256, dat.P384, dat.P521}
	cryptoAlgs := []dat.CryptoAlgorithm{dat.AES128GCMN, dat.AES256GCMN}
	var certificates []*dat.Certificate
	now := dat.NowUnixTimestamp()
	var i uint64 = 0
	for _, signAlg := range signAlgs {
		for _, cryptoAlg := range cryptoAlgs {
			for j := 0; j < 4; j++ {
				cid := i
				i++
				cert, err := dat.GenerateCertificate(cid, signAlg, cryptoAlg, now-10, now+600, 60)
				if err != nil {
					return err
				}
				certificates = append(certificates, cert)
			}
		}
	}
	fmt.Printf("Generated \n%s\n", manager.Export(dat.Pair))
	return manager.ImportCertificates(certificates, false)
}

func TestManager(t *testing.T) {
	manager := dat.NewManager()
	plain := randString()
	secure := randString()

	if err := genCertificate(manager); err != nil {
		t.Fatal(err)
	}

	certs := manager.ExportCertificates()
	var dats []string
	for _, cert := range certs {
		token, err := manager.IssueWithCertificate(cert, plain, secure)
		if err != nil {
			t.Fatal(err)
		}
		dats = append(dats, token)
	}

	exported := manager.Export(dat.Pair)
	manager2 := dat.NewManager()
	if err := manager2.Import(exported, true); err != nil {
		t.Fatal(err)
	}

	tag := "dat.manager"
	for _, token := range dats {
		d, err := dat.ParseDat(token)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%s.%s\n", tag, d.String())
		payload, err := manager2.Parse(d)
		if err != nil {
			t.Fatal(err)
		}
		sp, _ := payload.ToStringPayload()
		fmt.Printf("%s.%s\n", tag, sp.String())

		if sp.Plain != plain {
			t.Errorf("expected plain %s, got %s", plain, sp.Plain)
		}
		if sp.Secure != secure {
			t.Errorf("expected secure %s, got %s", secure, sp.Secure)
		}
	}
}
