package main

import (
	"github.com/rstms/rspamd-classes/classes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Initialize(t *testing.T) {
	log.SetOutput(os.Stdout)
	Verbose = true
	viper.SetDefault("verbose", true)
	InsecureSkipClientCertificateValidation = true
	viper.SetConfigFile("/etc/mabctl/config.yaml")
	viper.ReadInConfig()
}

func TestClasses(t *testing.T) {
	Initialize(t)
	config, err := classes.New("")
	require.Nil(t, err)
	require.NotNil(t, config)
	log.Printf("%+v", config)
}

func TestAccounts(t *testing.T) {
	Initialize(t)
	req := httptest.NewRequest("GET", "/filterctl/accounts/", nil)
	w := httptest.NewRecorder()
	api, ok := MAB(w)
	require.True(t, ok)
	require.NotNil(t, api)
	handleGetAccounts(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}
