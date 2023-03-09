package main

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	defer func() {
		os.Stdout = originalStdout
	}()
	os.Stdout = w

	os.Args = []string{"frogbot", "--version"}
	main()

	assert.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	expectedVersion := fmt.Sprintf("Frogbot version %s", utils.FrogbotVersion)
	assert.Equal(t, expectedVersion, strings.TrimSpace(string(out)))
}
