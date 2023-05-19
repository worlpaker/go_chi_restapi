package Log

import (
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErr(t *testing.T) {
	log.SetOutput(io.Discard)
	data := []struct {
		actual   bool
		expected bool
	}{
		{
			actual:   Err(nil),
			expected: false,
		},
		{
			actual:   Err(fmt.Errorf("error")),
			expected: true,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			assert.Equal(t, k.expected, k.actual)
		})
	}
}
