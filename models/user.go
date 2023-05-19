package models

type User struct {
	Email    string  `json:"Email"`
	Pwd      string  `json:"Pwd"`
	NickName string  `json:"NickName"`
	FullName *string `json:"FullName"`
}
