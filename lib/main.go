package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"qbit/lib/jwt"
)

func main() {
	pubkey := "MIGJAoGBAOfeiw_2wc7A-FyI8EH0KSX9_dI8RktzLox7vz3Qte5xKKqqWK5cYzJDoIDLmucPo6QdKfv597CwVBRJq21KNFxfHRYUQ1EE0WX7-c7eJ_W1zcONowRyh72LN6YeJYK1goEOR59yDM8p26PFDgUYnjmg2C2WvWJEB7iElbzUkJ81AgMBAAE"
	b, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		panic(err)
	}
	key, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		panic(err)
	}

	token := "eyJhbGdvIjoicnMyNTYiLCJ0eXAiOiJKV1QifQ.eyJ1c2VybmFtZSI6InNhaWZzdWxlbWFuIiwiaWF0IjoxNjIwODY4ODQwLCJleHAiOjE2MjA5NTUyNDB9.IfcsExgcrsXmRjZL00WRETU4WMxL47587naKlnhFZo0klytlOkti24kaQb98vd0C-XLjpABF1r-QElRqyt_u9KSmod1HpC2Cqj-qJdrDilYaFxEaa64mt6HJH31LXUUx5G3esuBMJGo_8ATeW810tjAA-eAimbQXaRFQeSul5Bo"
	fmt.Println(jwt.ValidateToken(token, key).Username)
}
