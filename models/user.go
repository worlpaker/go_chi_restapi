package models

type User struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	NickName string  `json:"nickname"`
	FullName *string `json:"fullname,omitempty"`
}
