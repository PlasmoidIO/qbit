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
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", username, password, address, database))
	if err != nil {
		return nil, err
	}
	query := "CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(100) NOT NULL, password VARCHAR(72) NOT NULL)"
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

func (u *UserProfileManager) AreCredentialsValid(username string, password string) bool {
	rows, err := u.Database.Query("SELECT * FROM users WHERE username=?", username)
	if err != nil || !rows.Next() {
		return false
	}

	type UserEntry struct {
		id       int64
		username string
		password string
	}

	var entry UserEntry
	if err := rows.Scan(&entry); err != nil {
		return false
	}
	return u.IsPasswordValid(password, entry.password)
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
