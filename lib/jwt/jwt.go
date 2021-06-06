package jwt

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type JwtValidator struct {
	key *rsa.PublicKey
}

func NewValidator() (*JwtValidator, error) {
	key, err := FetchPublicKey()
	if err != nil {
		return nil, err
	}
	return &JwtValidator{key: key}, nil
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

func (j *JwtValidator) ValidateToken(token string) (*JwtClaim, bool) {
	arr := strings.Split(token, ".")
	if len(arr) < 3 {
		return nil, false
	}

	header, err := j.ToHeader(arr[0])
	if err != nil {
		return nil, false
	}

	claim, err := j.ToClaim(arr[1])
	if err != nil {
		return claim, false
	}

	payload := fmt.Sprintf("%s.%s", header.String(), claim.String())
	hash := sha256.Sum256([]byte(payload))

	signature, err := base64.RawURLEncoding.DecodeString(arr[2])
	if err != nil {
		return claim, false
	}

	if err := rsa.VerifyPKCS1v15(j.key, crypto.SHA256, hash[:], signature); err != nil {
		return claim, false
	}

	return claim, true
}

func (j *JwtValidator) ToHeader(encoded string) (*JwtHeader, error) {
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

func (j *JwtValidator) ToClaim(encoded string) (*JwtClaim, error) {
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

func FetchPublicKey() (*rsa.PublicKey, error) {
	resp, err := http.Get("http://localhost:8080/api/pubkey")
	if err != nil {
		return nil, fmt.Errorf("error fetching pubkey: %s", err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
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

// @returns (token, success)
func GetToken(username string, password string) (string, error) {
	type Payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	payload := Payload{
		Username: username,
		Password: password,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := http.Post("http://localhost:8080/api/login", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return "", err
	}

	if err, has := responseData["error"]; has {
		errorMsg, ok := err.(string)
		if ok {
			return "", errors.New(errorMsg)
		}
	}
	if token, has := responseData["token"]; has {
		tok, ok := token.(string)
		if ok {
			return tok, nil
		}
	}

	return "", fmt.Errorf("invalid response")
}

func Register(username string, password string) error {
	type Payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	payload := Payload{
		Username: username,
		Password: password,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post("http://localhost:8080/api/register", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return err
	}

	if err, has := responseData["error"]; has {
		errorMsg, ok := err.(string)
		if ok {
			return errors.New(errorMsg)
		}
	}
	if username, has := responseData["username"]; has {
		username, ok := username.(string)
		if ok && username == payload.Username {
			return nil
		}
	}

	return fmt.Errorf("invalid response")
}
