package dat

import "errors"

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidCertificateFormat Error = "InvalidCertificateFormat"
	ErrInvalidSignatureKey      Error = "InvalidSignatureKey"
	ErrInvalidCryptoKey         Error = "InvalidCryptoKey"
	ErrGenerateSigningKeyError  Error = "GenerateSigningKeyError"
	ErrVerifyOnlyCertificate    Error = "VerifyOnlyCertificate"
	ErrEncryptError             Error = "EncryptError"
	ErrDecryptError             Error = "DecryptError"
	ErrSignError                Error = "SignError"
	ErrCidNotFound              Error = "CidNotFound"
	ErrSigningKeyNotExists      Error = "SigningKeyNotExists"
	ErrDuplicatedCid            Error = "DuplicatedCid"
	ErrInvalidBase64Format      Error = "InvalidBase64Format"
	ErrInvalidDat               Error = "InvalidDat"
)

func (e Error) IsCritical() bool {
	return !errors.Is(e, ErrInvalidDat)
}

func IsCritical(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := errors.AsType[Error](err); ok {
		return e.IsCritical()
	}
	return true
}
