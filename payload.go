package dat

import (
	"fmt"
)

type Payload struct {
	PlainBytes  []byte
	SecureBytes []byte
}

type StringPayload struct {
	Plain  string
	Secure string
}

func (p Payload) ToStringPayload() (StringPayload, error) {
	return StringPayload{
		Plain:  string(p.PlainBytes),
		Secure: string(p.SecureBytes),
	}, nil
}

func (p Payload) String() string {
	return fmt.Sprintf("%s %s", EncodeBase64URL(p.PlainBytes), EncodeBase64URL(p.SecureBytes))
}

func (sp StringPayload) String() string {
	return fmt.Sprintf("%s %s", sp.Plain, sp.Secure)
}
