package main

import (
	"fmt"
	"qbit/lib/jwt"
)

func main() {
	token, err := jwt.GetToken("saif", "saif")
	if err != nil {
		panic(err)
	}
	validator, err := jwt.NewValidator()
	if err != nil {
		panic(err)
	}

	claim, valid := validator.ValidateToken(fmt.Sprintf("a%sb", token))
	if claim != nil {
		fmt.Printf("Username: %s\nIssued at: %d\nExpire at: %d\nValid: %v\n\n", claim.Username, claim.IssuedAt, claim.ExpireAt, valid)
	} else {
		fmt.Printf("Valid: %v\n", valid)
	}
}
