package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
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

	username := ""
	password := ""

	if r.Header.Get("Content-Type") == "application/json" {
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			fmt.Printf("error parsing json: %s\n", err)
			return
		}

		if u, has := data["username"]; has {
			u, ok := u.(string)
			if ok {
				username = u
			}
		}

		if p, has := data["password"]; has {
			p, ok := p.(string)
			if ok {
				password = p
			}
		}
	} else {
		if err := r.ParseForm(); err != nil {
			respondWithJSON(w, 400, ErrorResponse{"invalid data specified"})
			return
		}

		username = r.FormValue("username")
		password = r.FormValue("password")
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

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	type SuccessResponse struct {
		Token string `json:"token"`
	}

	username := ""
	password := ""

	if r.Header.Get("Content-Type") == "application/json" {
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			fmt.Printf("error parsing json: %s\n", err)
			return
		}

		if u, has := data["username"]; has {
			u, ok := u.(string)
			if ok {
				username = u
			}
		}

		if p, has := data["password"]; has {
			p, ok := p.(string)
			if ok {
				password = p
			}
		}
	} else {
		if err := r.ParseForm(); err != nil {
			respondWithJSON(w, 400, ErrorResponse{"invalid data specified"})
			return
		}

		username = r.FormValue("username")
		password = r.FormValue("password")
	}

	if username == "" || password == "" {
		respondWithJSON(w, 400, ErrorResponse{"invalid data: must specify 'username' and 'password'"})
		return
	}

	if !a.UserProfileManager.AreCredentialsValid(username, password) {
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

func main() {
	privateFile, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		log.Fatalf("error reading private key file: %s\n", err)
		return
	}
	publicFile, err := ioutil.ReadFile("public_key.pem")
	if err != nil {
		log.Fatalf("error reading public key file: %s\n", err)
		return
	}
	privateKey, err := authentication.ReadPrivateKey(privateFile)
	if err != nil {
		log.Fatalf("private key invalid")
		return
	}
	if _, err := authentication.ReadPublicKey(publicFile); err != nil {
		log.Fatalf("public key invalid")
		return
	}
	jwtHandler := authentication.NewJwtHandler(privateKey, 24)

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
		_, _ = fmt.Fprint(w, string(publicFile))
	})

	fmt.Println("Listening on port 80...")
	if err := http.ListenAndServe(":80", router); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}
