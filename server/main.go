package main

import (
	"fmt"
	"qbit/lib/jwt"
	"qbit/server/authentication"
)

func main() {
	priv, err := authentication.ReadPrivateKeyFile("private_key.pem")
	if err != nil {
		panic(err)
	}
	pub, err := authentication.ReadPublicKeyFile("public_key.pem")
	if err != nil {
		panic(err)
	}
	handler := authentication.NewJwtHandler(priv, 24)

	token := handler.GenerateToken("saif")
	claim, valid := jwt.ValidateToken(token, pub)
	if valid {
		fmt.Printf("Username: %s\n", claim.Username)
	} else {
		fmt.Println("Not valid.")
	}
}
