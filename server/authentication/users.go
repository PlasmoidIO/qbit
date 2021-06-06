package authentication

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

type UserProfileManager struct {
	Database *sql.DB
}

func NewProfileManager(address string, database string, username string, password string) (*UserProfileManager, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", username, password, address, database))
	if err != nil {
		return nil, err
	}
	query := "CREATE TABLE users (uuid BINARY(16) PRIMARY KEY, username VARCHAR(100) NOT NULL, password VARCHAR(72) NOT NULL)"
	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("initializing table error - %s", err)
	}

	return &UserProfileManager{db}, nil
}

func (u *UserProfileManager) AreCredentialsValid(username string, password string) bool {
	return true
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
