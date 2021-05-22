package authentication

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func ReadPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
	data, rest := pem.Decode(contents)
	if len(rest) > 0 {
		return nil, fmt.Errorf("private rsa file too large")
	}

	return x509.ParsePKCS1PrivateKey(data.Bytes)
}

func ReadPublicKeyFile(path string) (*rsa.PublicKey, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
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
