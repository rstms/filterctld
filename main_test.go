package main

import (
	"github.com/rstms/rspamd-classes/classes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClasses(t *testing.T) {
	config, err := classes.New("")
	require.Nil(t, err)
	require.NotNil(t, config)
	log.Printf("%+v", config)
}

func TestAccounts(t *testing.T) {

	Verbose = true
	InsecureSkipClientCertificateValidation = true
	req := httptest.NewRequest("GET", "/filterctl/accounts/", nil)
	req.Header.Set("X-Api-Key", viper.GetString("api-key"))
	req.Header.Set("X-Admin-Username", viper.GetString("admin-username"))
	req.Header.Set("X-Admin-Password", viper.GetString("admin-password"))
	w := httptest.NewRecorder()
	handleGetAccounts(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}
