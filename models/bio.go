package models

import "backend/internal/param"

type ProfileBio struct {
	NickName string `json:"nickname"`
	Info     string `json:"info"`
}

// Validate checks if the ProfileBio's 'Info' field is empty.
// Returns true if 'Info' is empty, indicating validation failure.
func (b *ProfileBio) Validate() (ok bool) {
	if param.IsNull(b.Info) {
		ok = true
		return
	}
	return
}
