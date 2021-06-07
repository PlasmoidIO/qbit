package authentication

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type UserProfileManager struct {
	Database *sql.DB
}

func NewProfileManager(address string, database string, username string, password string) (*UserProfileManager, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/", username, password, address))
	fmt.Printf("Initializing profile manager at address: %s@%s:%s/%s\n", username, address, password, database)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + database); err != nil {
		return nil, err
	}
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", username, password, address, database))
	if err != nil {
		return nil, err
	}
	query := "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(100) NOT NULL, password VARCHAR(72) NOT NULL)"
	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("initializing table error - %s", err)
	}

	return &UserProfileManager{db}, nil
}

// check if user already exists
func (u *UserProfileManager) RegisterUser(username string, password string) error {
	rows, err := u.Database.Query("SELECT * FROM users WHERE username=?", username)
	if err != nil {
		return err
	}
	if rows.Next() {
		return fmt.Errorf("user with that username already exists!")
	}
	hash, err := u.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = u.Database.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hash)
	return err
}

func (u *UserProfileManager) AreCredentialsValid(username string, password string) (string, bool) {
	rows, err := u.Database.Query("SELECT username, password FROM users WHERE username=?", username)
	if err != nil || !rows.Next() {
		return "", false
	}

	var user string
	var hash string
	if err := rows.Scan(&user, &hash); err != nil {
		return "", false
	}
	return user, u.IsPasswordValid(password, hash)
}

func (u *UserProfileManager) IsPasswordValid(password string, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (u *UserProfileManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
