package authentication

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func (j *JwtHandler) GenerateToken(username string) string {
	header := JwtHeader{
		Algo: "RS256",
		Type: "JWT",
	}

	claim := JwtClaim{
		Username: username,
		IssuedAt: time.Now().Unix(),
		ExpireAt: time.Now().Add(time.Duration(j.ExpirationHours) * time.Hour).Unix(),
	}

	signature := j.createSignature(header, claim)

	fmt.Printf("[+] Token generated for user: %s\n", username)

	return fmt.Sprintf("%s.%s.%s", header.String(), claim.String(), signature)
}

func (j *JwtHandler) createSignature(header JwtHeader, claim JwtClaim) string {
	payload := fmt.Sprintf("%s.%s", header.String(), claim.String())
	hash := sha256.Sum256([]byte(payload))

	signature, err := rsa.SignPKCS1v15(rand.Reader, j.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatalf("Error signing: %s\n", err)
	}

	sig := base64.RawURLEncoding.EncodeToString(signature)
	return sig
}
