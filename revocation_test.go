package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddRevocationTokenTypeHints(t *testing.T) {
	testCases := []struct {
		name     string
		have     []string
		expected []string
	}{
		{
			"ShouldHandleSingleValue",
			[]string{"foo"},
			[]string{"foo"},
		},
		{
			"ShouldHandleMultipleValues",
			[]string{"foo", "bar"},
			[]string{"foo", "bar"},
		},
		{
			"ShouldHandleDuplicateValues",
			[]string{"foo", "bar", "foo"},
			[]string{"foo", "bar"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var have []string

			f := AddRevocationTokenTypes(tc.have...)

			have = f.appendTokenTypeHints(have)

			assert.Equal(t, tc.expected, have)
		})
	}
}
