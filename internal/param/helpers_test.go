package param

import (
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsParamNull(t *testing.T) {
	log.SetOutput(io.Discard)
	testCases := []struct {
		input    []string
		expected bool
	}{
		{[]string{"a", "b", "c"}, false},
		{[]string{"a", "", "c"}, true},
		{[]string{"", "", ""}, true},
		{[]string{""}, true},
		{[]string{}, false},
	}

	for _, k := range testCases {
		actual := IsNull(k.input...)
		assert.Equal(t, k.expected, actual)
	}
}
