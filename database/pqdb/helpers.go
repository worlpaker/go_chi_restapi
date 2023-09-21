package pqdb

import (
	Log "backend/internal/log"
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

// HandleTransaction handles the commit or rollback of a SQL transaction based on the error value.
func HandleTransaction(tx *sql.Tx, err *error) {
	switch *err {
	case nil:
		// Commit the transaction if the error is nil (successful operation)
		if commit_err := tx.Commit(); Log.Err(commit_err) {
			*err = commit_err
		}
	default:
		// Rollback the transaction if the error is not nil (error condition)
		tx.Rollback()
	}
}

// HashPassword takes a password string and hashes it using bcrypt algorithm.
func HashPassword(pwd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if Log.Err(err) {
		return "", err
	}
	return string(hash), nil
}
