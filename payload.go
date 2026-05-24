package dat

import (
	"fmt"
)

type DatPayload struct {
	PlainBytes  []byte
	SecureBytes []byte
}

type StringPayload struct {
	Plain  string
	Secure string
}

func (p DatPayload) ToStringPayload() (StringPayload, error) {
	return StringPayload{
		Plain:  string(p.PlainBytes),
		Secure: string(p.SecureBytes),
	}, nil
}

func (p DatPayload) String() string {
	return fmt.Sprintf("%s %s", EncodeBase64URL(p.PlainBytes), EncodeBase64URL(p.SecureBytes))
}

func (sp StringPayload) String() string {
	return fmt.Sprintf("%s %s", sp.Plain, sp.Secure)
}
