package langmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLang(t *testing.T) {
	lang, err := GetLang("en-US,en;q=0.5")
	assert.Nil(t, err)
	assert.Equal(t, "not found", lang.Errors.NotFound)
	lang, err = GetLang("tr-TR,tr;q=0.9")
	assert.Nil(t, err)
	assert.Equal(t, "bulunamadi", lang.Errors.NotFound)
}
