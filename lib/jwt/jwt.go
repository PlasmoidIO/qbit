package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

type JwtHeader struct {
	Algo string `json:"alg"`
	Type string `json:"typ"`
}

type JwtClaim struct {
	Username string `json:"username"`
	IssuedAt int64  `json:"iat"`
	ExpireAt int64  `json:"exp"`
}

func (j *JwtHeader) String() string {
	b, err := json.Marshal(j)
	if err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (j *JwtClaim) String() string {
	b, err := json.Marshal(j)
	if err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func ValidateToken(token string, key *rsa.PublicKey) (*JwtClaim, bool) {
	arr := strings.Split(token, ".")
	if len(arr) < 3 {
		return nil, false
	}

	header, err := ToHeader(arr[0])
	if err != nil {
		panic(err)
		return nil, false
	}

	claim, err := ToClaim(arr[1])
	if err != nil {
		panic(err)
		return claim, false
	}

	payload := fmt.Sprintf("%s.%s", header.String(), claim.String())
	fmt.Printf("(jwt/jwt.go) Header: %v\nClaim: %v\n\n", *header, *claim)
	hash := sha256.Sum256([]byte(payload))

	signature, err := base64.RawURLEncoding.DecodeString(arr[2])
	if err != nil {
		return claim, false
	}

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
		panic(err)
	}

	return claim, true
}

func ToHeader(encoded string) (*JwtHeader, error) {
	var header JwtHeader
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

func ToClaim(encoded string) (*JwtClaim, error) {
	var claim JwtClaim
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &claim); err != nil {
		return nil, err
	}
	return &claim, nil
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
	key, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("could not parse pubkey")
	}
	return pub, nil
}
