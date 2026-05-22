package dat

import (
	"fmt"
	"strconv"
	"strings"
)

type Dat struct {
	data      []byte
	Expire    uint64
	Cid       uint64
	plainPos  int
	securePos int
	Signature []byte
}

func (d *Dat) Plain() ([]byte, error) {
	return DecodeBase64URL(string(d.data[d.plainPos : d.securePos-1]))
}

func (d *Dat) Secure() ([]byte, error) {
	return DecodeBase64URL(string(d.data[d.securePos:]))
}

func (d *Dat) BodyBytes() []byte {
	return d.data
}

func (d *Dat) String() string {
	return fmt.Sprintf("%d.%x", d.Expire, d.Cid)
}

func ParseDat(s string) (*Dat, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 5 {
		return nil, ErrInvalidDat
	}

	expire, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || expire <= NowUnixTimestamp() {
		return nil, ErrInvalidDat
	}

	cid, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return nil, ErrInvalidDat
	}

	lastDotIdx := strings.LastIndex(s, ".")
	body := s[:lastDotIdx]
	signatureB64 := s[lastDotIdx+1:]

	signature, err := DecodeBase64URL(signatureB64)
	if err != nil {
		return nil, err
	}

	p0 := len(parts[0]) + 1      // after expire
	p1 := p0 + len(parts[1]) + 1 // after expire.cid
	plainPos := p1
	p2 := p1 + len(parts[2]) + 1 // after expire.cid.plain
	securePos := p2

	return &Dat{
		data:      []byte(body),
		Expire:    expire,
		Cid:       cid,
		plainPos:  plainPos,
		securePos: securePos,
		Signature: signature,
	}, nil
}
