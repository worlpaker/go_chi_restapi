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

func (u *User) ValidateRegister() (ok bool) {
	if param.IsNull(u.Email, u.Password, u.NickName) {
		ok = true
		return
	}
	return
}

func (u *User) ValidateLogin() (ok bool) {
	if param.IsNull(u.Email, u.Password) {
		ok = true
		return
	}
	return
}
