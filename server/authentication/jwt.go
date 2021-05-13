package authentication

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type JwtHandler struct {
	PrivateKey      *rsa.PrivateKey
	ExpirationHours int
}

type JwtHeader struct {
	Algo string `json:"algo"`
	Type string `json:"typ"`
}

type JwtClaim struct {
	Username string `json:"username"`
	IssuedAt int64  `json:"iat"`
	ExpireAt int64  `json:"exp"`
}

func NewJwtHandler(expirationHours int) JwtHandler {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Public key: %s\n", base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey)))

	return JwtHandler{
		PrivateKey:      key,
		ExpirationHours: expirationHours,
	}
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

func (j *JwtHandler) GenerateToken(username string) string {
	header := JwtHeader{
		Algo: "rs256",
		Type: "JWT",
	}

	claim := JwtClaim{
		Username: username,
		IssuedAt: time.Now().Unix(),
		ExpireAt: time.Now().Add(time.Duration(j.ExpirationHours) * time.Hour).Unix(),
	}

	signature := j.createSignature(header, claim)

	return fmt.Sprintf("%s.%s.%s", header.String(), claim.String(), signature)
}

func (j *JwtHandler) createSignature(header JwtHeader, claim JwtClaim) string {
	payload := fmt.Sprintf("%s.%s", header.String(), claim.String())
	hash := sha256.Sum256([]byte(payload))

	signature, err := rsa.SignPSS(rand.Reader, j.PrivateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		log.Fatalf("Error signing: %s\n", err)
	}

	return base64.RawURLEncoding.EncodeToString(signature)
}
