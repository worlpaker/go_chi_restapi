package models

import (
	"backend/internal/param"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	NickName string `json:"nickname"`
	FullName string `json:"fullname,omitempty"`
}

// ValidateRegister checks if required User fields for registration are not empty.
// Returns true if any field is empty, indicating validation failure.
func (u *User) ValidateRegister() (ok bool) {
	if param.IsNull(u.Email, u.Password, u.NickName) {
		ok = true
		return
	}
	return
}

// ValidateLogin checks if required User fields for login are not empty.
// Returns true if any field is empty, indicating validation failure.
func (u *User) ValidateLogin() (ok bool) {
	if param.IsNull(u.Email, u.Password) {
		ok = true
		return
	}
	return
}
