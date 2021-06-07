package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"qbit/server/authentication"
)

type App struct {
	JwtHandler         authentication.JwtHandler
	UserProfileManager *authentication.UserProfileManager
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type SuccessResponse struct {
		Username string `json:"username"`
	}

	username, password, proceed := getUsernamePasswordPair(w, r)
	if !proceed {
		return
	}

	if username == "" || password == "" {
		respondWithJSON(w, 400, ErrorResponse{"invalid data: must specify 'username' and 'password'"})
		return
	}

	if err := a.UserProfileManager.RegisterUser(username, password); err != nil {
		respondWithJSON(w, 400, ErrorResponse{err.Error()})
		return
	}

	respondWithJSON(w, 200, SuccessResponse{username})
}

// function to get "username" field and "password" field from request body
func getUsernamePasswordPair(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	var username string
	var password string

	switch contentType := r.Header.Get("Content-Type"); contentType {
	case "application/json":
		type IncomingDataPacket struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var packet IncomingDataPacket

		if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
			fmt.Printf("invaild data received: %s\n", err)
			respondWithJSON(w, 400, ErrorResponse{"invalid json data submitted"})
			return username, password, false
		}
		username, password = packet.Username, packet.Password
	case "application/x-www-form-urlencoded":
		if r.ParseForm() != nil {
			respondWithJSON(w, 400,
				ErrorResponse{"invalid data submitted"})
			return username, password, false
		}
		username, password = r.FormValue("username"), r.FormValue("password")
	default:
		respondWithJSON(w, 400, ErrorResponse{"invalid content type: '" + contentType + "'"})
		return username, password, false
	}

	return username, password, true
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type SuccessResponse struct {
		Token string `json:"token"`
	}

	username, password, proceed := getUsernamePasswordPair(w, r)
	if !proceed {
		return
	}

	if username == "" || password == "" {
		respondWithJSON(w, 400, ErrorResponse{"invalid data: must specify 'username' and 'password'"})
		return
	}

	var valid bool
	username, valid = a.UserProfileManager.AreCredentialsValid(username, password)
	if !valid {
		respondWithJSON(w, 400, ErrorResponse{"credentials provided are invalid"})
		return
	}

	token := a.JwtHandler.GenerateToken(username)
	respondWithJSON(w, 200, SuccessResponse{token})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	res, err := json.Marshal(payload)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(res)
}

func getPublicKeyPem(key *rsa.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: b,
	})
	return string(keyPem), nil
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error creating key pair: %s\n", err)
		return
	}

	pubKey, err := getPublicKeyPem(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("error marshalling to pubkey: %s\n", err)
		return
	}

	jwtHandler := authentication.JwtHandler{
		PrivateKey:      privateKey,
		ExpirationHours: 24,
	}

	profileManager, err := authentication.NewProfileManager("srv-captain--qbit-db:3306", "qbit", "root", "qbit")
	if err != nil {
		log.Fatalf("error initializing profile manager: %s\n", err)
		return
	}
	defer profileManager.Database.Close()

	app := App{
		JwtHandler:         jwtHandler,
		UserProfileManager: profileManager,
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/login", app.login)
	router.HandleFunc("/api/register", app.register)
	router.HandleFunc("/api/pubkey", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, pubKey)
	})
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://google.com/", 302)
	})

	fmt.Println("Listening on port 80...")
	if err := http.ListenAndServe(":80", router); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}
