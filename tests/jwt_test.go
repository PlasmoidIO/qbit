package tests

import (
	"qbit/lib/jwt"
	"testing"
)

func TestToken(t *testing.T) {
	validator, err := jwt.NewValidator()
	if err != nil {
		t.Error(err)
	}
	tok, err := jwt.GetToken("saif", "London2005")
	if err != nil {
		t.Error(err)
	}
	claim, valid := validator.ValidateToken(tok)
	if claim == nil || !valid {
		t.Fatal("token invalid")
	}
	t.Logf("Claim:\nUsername: %s\n\n", claim.Username)
}
