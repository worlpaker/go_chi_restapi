package models

type LangugeCode string

const Lang LangugeCode = "lang"

type LangCodes struct {
	En LangMsg `json:"en-US"`
	Tr LangMsg `json:"tr-TR"`
}

type LangMsg struct {
	Success Success `json:"success"`
	Errors  Errors  `json:"errors"`
}

type Success struct {
	Register  string `json:"register"`
	Login     string `json:"login"`
	AddBio    string `json:"addbio"`
	EditBio   string `json:"editbio"`
	DeleteBio string `json:"deletebio"`
	Logout    string `json:"logout"`
}

type Errors struct {
	NotFound string `json:"not_found"`
}
