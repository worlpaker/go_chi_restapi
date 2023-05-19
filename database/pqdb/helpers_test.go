package pqdb

import (
	"errors"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	log.SetOutput(io.Discard)
	data := []struct {
		data     string
		expected error
	}{
		{
			data:     "test123",
			expected: nil,
		},
		{
			data: `testtesttesttesttest
				testtesttesttesttesttest
				testtesttesttesttesttesttesttesttest`,
			expected: errors.New("bcrypt: password length exceeds 72 bytes"),
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			_, err := HashPassword(k.data)
			assert.Equal(t, k.expected, err)
		})
	}
}
