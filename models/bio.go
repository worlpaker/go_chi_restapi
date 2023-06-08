package models

import "backend/pkg/helpers/param"

type ProfileBio struct {
	NickName string `json:"nickname"`
	Info     string `json:"info"`
}

func (b *ProfileBio) Validate() (ok bool) {
	if param.IsNull(b.Info) {
		ok = true
		return
	}
	return
}
