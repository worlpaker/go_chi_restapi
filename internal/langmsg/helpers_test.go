package langmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLang(t *testing.T) {
	p := ParseLang("en-US,en;q=0.5")
	assert.Equal(t, "en-US", p)
	p = ParseLang("en-US")
	assert.Equal(t, "en-US", p)
}
