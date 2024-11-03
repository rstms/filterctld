package main

import (
	"github.com/rstms/rspamd-classes/classes"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVersion(t *testing.T) {
	config, err := classes.New("")
	require.Nil(t, err)
	require.NotNil(t, config)
}
