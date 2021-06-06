package authentication

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ReadPrivateKey(contents []byte) (*rsa.PrivateKey, error) {
	data, rest := pem.Decode(contents)
	if len(rest) > 0 {
		return nil, fmt.Errorf("private rsa file too large")
	}

	return x509.ParsePKCS1PrivateKey(data.Bytes)
}

func ReadPublicKey(contents []byte) (*rsa.PublicKey, error) {
	data, rest := pem.Decode(contents)
	if len(rest) > 0 {
		return nil, fmt.Errorf("public rsa file too large")
	}
	obj, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := obj.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a pubkey file")
	}
	return key, nil
}
