package main

import (
	"fmt"
	"qbit/server/authentication"
)

func main() {
	handler := authentication.NewJwtHandler(24)
	token := handler.GenerateToken("saifsuleman")
	fmt.Printf("The token is: %s\n", token)
}
