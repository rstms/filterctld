package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rstms/mabctl/api"
	"github.com/rstms/rspamd-classes/classes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Initialize(t *testing.T) {
	log.SetOutput(os.Stdout)
	InsecureSkipClientCertificateValidation = true
	setViperDefaults()
	viper.SetDefault("verbose", true)
	viper.SetConfigFile("./testdata/config.yaml")
	viper.ReadInConfig()
	setVerbose(viper.GetBool("verbose"))
}

func setVerbose(enable bool) {
	Verbose = enable
	viper.Set("verbose", enable)
}

func callHandler(path string, handler func(http.ResponseWriter, *http.Request), r *http.Request) *http.Response {
	mux := http.NewServeMux()
	mux.HandleFunc(path, handler)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Result()
}

func requestBuffer(t *testing.T, request any) io.Reader {
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	return bytes.NewBuffer(data)
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

func TestGetUserBooks(t *testing.T) {
	Initialize(t)
	req := httptest.NewRequest("GET", fmt.Sprintf("/filterctl/books/%s/", viper.GetString("test_user")), nil)
	result := callHandler("GET /filterctl/books/{user}/", handleListBooks, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}

func TestGetUserDump(t *testing.T) {
	Initialize(t)
	req := httptest.NewRequest("GET", fmt.Sprintf("/filterctl/dump/%s/", viper.GetString("test_user")), nil)
	result := callHandler("GET /filterctl/dump/{user}/", handleGetUserDump, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}

func TestCreateBook(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book := viper.GetString("test_book")
	response := createBook(t, user, book)
	log.Printf("%+v", response)
}

func createBook(t *testing.T, user, book string) *http.Response {
	request := CreateBookRequest{
		Username:    user,
		Bookname:    book,
		Description: book,
	}
	req := httptest.NewRequest("POST", "/filterctl/book/", requestBuffer(t, &request))
	response := callHandler("POST /filterctl/book/", handleAddBook, req)
	require.Equal(t, response.StatusCode, http.StatusOK)
	return response
}

func TestAddAddress(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book1 := viper.GetString("test_book")
	book2 := book1 + "_2"
	addr := viper.GetString("test_address")
	if isBook(t, user, book1) {
		deleteBook(t, user, book1)
	}
	if isBook(t, user, book2) {
		deleteBook(t, user, book2)
	}
	createBook(t, user, book1)
	createBook(t, user, book2)

	addAddress(t, user, book1, addr)
	require.True(t, hasAddress(t, user, book1, addr))
	require.False(t, hasAddress(t, user, book2, addr))

	deleteAddress(t, user, book1, addr)
	require.False(t, hasAddress(t, user, book1, addr))
	require.False(t, hasAddress(t, user, book2, addr))

	addAddress(t, user, book2, addr)
	require.False(t, hasAddress(t, user, book1, addr))
	require.True(t, hasAddress(t, user, book2, addr))

	deleteAddress(t, user, book2, addr)
	require.False(t, hasAddress(t, user, book1, addr))
	require.False(t, hasAddress(t, user, book2, addr))

	addAddress(t, user, book1, addr)
	require.True(t, hasAddress(t, user, book1, addr))
	require.False(t, hasAddress(t, user, book2, addr))

	Verbose = true
	viper.Set("verbose", true)
	addAddress(t, user, book2, addr)
	viper.Set("verbose", false)
	Verbose = false

	require.False(t, hasAddress(t, user, book1, addr))
	require.True(t, hasAddress(t, user, book2, addr))

	deleteBook(t, user, book1)
	deleteBook(t, user, book2)
}

func addAddress(t *testing.T, user, book, address string) {
	request := AddAddressRequest{
		Username: user,
		Bookname: book,
		Address:  address,
		Name:     address,
	}
	req := httptest.NewRequest("POST", "/filterctl/address/", requestBuffer(t, &request))
	result := callHandler("POST /filterctl/address/", handleAddAddress, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}

func TestDeleteBook(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book := viper.GetString("test_book")
	if !isBook(t, user, book) {
		createBook(t, user, book)
	}
	response := deleteBook(t, user, book)
	log.Printf("%+v", response)
}

func deleteBook(t *testing.T, user, book string) *http.Response {
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/filterctl/book/%s/%s/", user, book), nil)
	response := callHandler("DELETE /filterctl/book/{user}/{book}/", handleDeleteBook, req)
	require.Equal(t, response.StatusCode, http.StatusOK)
	return response
}

func TestDeleteAddress(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book := viper.GetString("test_book")
	addr := viper.GetString("test_address")
	if isBook(t, user, book) {
		deleteBook(t, user, book)
	}
	createBook(t, user, book)
	addAddress(t, user, book, addr)
	require.True(t, hasAddress(t, user, book, addr))
	response := deleteAddress(t, user, book, addr)
	log.Printf("%+v", response)
	require.False(t, hasAddress(t, user, book, addr))
	deleteBook(t, user, book)
}

func deleteAddress(t *testing.T, user, book, address string) *http.Response {
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/filterctl/address/%s/%s/%s/", user, book, address), nil)
	response := callHandler("DELETE /filterctl/address/{user}/{book}/{address}/", handleDeleteAddress, req)
	require.Equal(t, response.StatusCode, http.StatusOK)
	return response
}

func isBook(t *testing.T, userName, bookName string) bool {
	req := httptest.NewRequest("GET", fmt.Sprintf("/filterctl/books/%s/", userName), nil)
	result := callHandler("GET /filterctl/books/{user}/", handleListBooks, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	defer result.Body.Close()
	data, err := io.ReadAll(result.Body)
	require.Nil(t, err)
	response := api.BooksResponse{}
	err = json.Unmarshal(data, &response)
	require.Nil(t, err)
	for _, book := range response.Books {
		if book.BookName == bookName {
			return true
		}
	}
	return false
}

func hasAddress(t *testing.T, userName, bookName, testAddress string) bool {
	require.True(t, isBook(t, userName, bookName))
	req := httptest.NewRequest("GET", fmt.Sprintf("/filterctl/dump/%s/", userName), nil)
	result := callHandler("GET /filterctl/dump/{user}/", handleGetUserDump, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	defer result.Body.Close()
	data, err := io.ReadAll(result.Body)
	require.Nil(t, err)
	response := DumpResponse{}
	err = json.Unmarshal(data, &response)
	require.Nil(t, err)
	for name, addresses := range response.Books {
		if name == bookName {
			for _, address := range addresses {
				if address == testAddress {
					return true
				}
			}
		}
	}
	return false
}

func TestIsBook(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book := viper.GetString("test_book")
	if isBook(t, user, book) {
		deleteBook(t, user, book)
	}
	require.False(t, isBook(t, user, book))
	createBook(t, user, book)
	require.True(t, isBook(t, user, book))
	deleteBook(t, user, book)
	require.False(t, isBook(t, user, book))
}

func TestHasAddress(t *testing.T) {
	Initialize(t)
	user := viper.GetString("test_user")
	book := viper.GetString("test_book")
	addr := viper.GetString("test_address")

	if isBook(t, user, book) {
		deleteBook(t, user, book)
	}
	createBook(t, user, book)

	require.False(t, hasAddress(t, user, book, addr))
	setVerbose(true)
	addAddress(t, user, book, addr)
	setVerbose(false)
	require.True(t, hasAddress(t, user, book, addr))
	setVerbose(true)
	deleteAddress(t, user, book, addr)
	setVerbose(false)
	require.False(t, hasAddress(t, user, book, addr))

	deleteBook(t, user, book)
}
