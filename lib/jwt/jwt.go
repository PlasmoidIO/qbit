package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type JwtHeader struct {
	Algo string `json:"algo"`
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

func ValidateToken(token string, pub *rsa.PublicKey) *JwtClaim {
	arr := strings.Split(token, ".")
	if len(arr) < 3 {
		return nil
	}

	header, err := ToHeader(arr[0])
	if err != nil {
		panic(err)
		return nil
	}

	claim, err := ToClaim(arr[1])
	if err != nil {
		panic(err)
		return nil
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", header.String(), claim.String())))

	signature, err := base64.RawURLEncoding.DecodeString(arr[2])
	if err != nil {
		return nil
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash[:], signature, nil); err != nil {
		panic(err)
		return nil
	}

	return claim
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
