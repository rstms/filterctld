package main

import (
	"bytes"
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
func TestRescanOne(t *testing.T) {
	Initialize(t)
	viper.SetDefault("cert", "/home/mkrueger/ssl/filterctl.pem")
	viper.SetDefault("key", "/home/mkrueger/ssl/filterctl.key")
	viper.SetDefault("ca", "/etc/ssl/keymaster.pem")
	viper.SetDefault("server_url", "https://bitbucket.rstms.net:4443")

	request := `{ "Username": "mkrueger@rstms.net", "Folder": "/INBOX", "MessageIds": ["0100019110a8e144-f106a68f-b3dd-46fc-9468-042cc93f2c30-000000@email.amazonses.com"]}`
	req := httptest.NewRequest("POST", "/filterctl/rescan/", bytes.NewBuffer([]byte(request)))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}

func TestRescanFolder(t *testing.T) {
	Initialize(t)
	viper.SetDefault("cert", "/home/mkrueger/ssl/filterctl.pem")
	viper.SetDefault("key", "/home/mkrueger/ssl/filterctl.key")
	viper.SetDefault("ca", "/etc/ssl/keymaster.pem")
	viper.SetDefault("server_url", "https://bitbucket.rstms.net:4443")

	request := `{ "Username": "mkrueger@rstms.net", "Folder": "/INBOX" }`
	req := httptest.NewRequest("POST", "/filterctl/rescan/", bytes.NewBuffer([]byte(request)))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}
