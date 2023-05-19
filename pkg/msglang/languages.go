package msglang

import (
	"backend/models"
	Log "backend/pkg/helpers/log"
	_ "embed"
	"encoding/json"
)

//go:embed messages.json
var file []byte

func GetLang(l string) (language *models.LangMsg, err error) {
	var data models.LangCodes
	if err = json.Unmarshal(file, &data); Log.Err(err) {
		return
	}
	switch ParseLang(l) {
	case "en-US":
		language = &data.En
	case "tr-TR":
		language = &data.Tr
	default:
		language = &data.En
	}
	return
}
