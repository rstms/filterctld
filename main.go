package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rstms/mabctl/api"
	"github.com/rstms/rspamd-classes/classes"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const serverName = "filterctld"
const defaultConfigFile = "/etc/mail/filter_rspamd_classes.json"
const defaultLogFile = "/var/log/filterctld"
const defaultPort = 2016
const SHUTDOWN_TIMEOUT = 5
const Version = "1.1.13"

var Verbose bool
var Debug bool
var InsecureSkipClientCertificateValidation bool
var mabLock sync.Mutex

var configFile string

var (
	signalFlag = flag.String("s", "", `send signal:
    stop - shutdown
    reload - reload config
    `)
	shutdown = make(chan struct{})
	reload   = make(chan struct{})
)

type ClassesResponse struct {
	api.Response
	Classes []classes.SpamClass
}

type ClassResponse struct {
	api.Response
	Class string
}

type ScanResponse struct {
	api.Response
	Books []string
}

type PasswordResponse struct {
	api.Response
	Password string
}

type DumpResponse struct {
	api.Response
	Classes  []classes.SpamClass
	Books    map[string][]string
	Password string
}

type RescanRequest struct {
	Username   string
	Folder     string
	MessageIds []string
}

func MAB(w http.ResponseWriter) (*api.Controller, bool) {
	mabLock.Lock()
	defer mabLock.Unlock()
	api, err := api.NewAddressBookController()
	if err != nil {
		fail(w, "system", "address book controller", fmt.Sprintf("api init failed: %v", err), http.StatusInternalServerError)
		return nil, false
	}
	return api, true
}

func fail(w http.ResponseWriter, user, request, message string, status int) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(api.Response{User: user, Request: request, Success: false, Message: message})
}

func succeed(w http.ResponseWriter, message string, result interface{}) {
	status := http.StatusOK
	log.Printf("  [%d] %s", status, message)
	if Verbose {
		dump, err := json.MarshalIndent(result, "", "  ")
		if err != nil {

			log.Fatalln("failure marshalling response:", err)
		}
		log.Println(string(dump))
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func checkClientCert(w http.ResponseWriter, r *http.Request) bool {
	if InsecureSkipClientCertificateValidation {
		return true
	}
	usernameHeader, ok := r.Header["X-Client-Cert-Dn"]
	if !ok {
		fail(w, "system", "client certificate check", "missing client cert DN", http.StatusBadRequest)
		return false
	}

	if Verbose {
		log.Printf("client cert dn: %s\n", usernameHeader[0])
	}

	if usernameHeader[0] == "CN=filterctl" || usernameHeader[0] == "CN=mabctl" {
		return true
	}

	fail(w, "system", "client certificate check", fmt.Sprintf("client cert (%s) != filterctl", usernameHeader[0]), http.StatusBadRequest)
	return false
}

func logConfig(w http.ResponseWriter, config *classes.SpamClasses, label, user, request string) error {

	if Verbose {
		data, err := json.MarshalIndent(&config.Classes, "", "  ")
		if err != nil {
			return err
		}
		log.Printf("BEGIN-%s: user=%s request=%s\n%s\nEND-%s\n", label, user, request, string(data), label)
	}
	return nil
}

func readConfig(w http.ResponseWriter, user, request string) (*classes.SpamClasses, bool) {
	config, err := classes.New(configFile)
	if err != nil {
		fail(w, user, request, "configuration read failed", http.StatusInternalServerError)
		return nil, false
	}
	err = logConfig(w, config, "readConfig", user, request)
	if err != nil {
		msg := fmt.Sprintf("readConfig: logConfig failed: %v", err)
		fail(w, user, request, msg, http.StatusInternalServerError)
		return nil, false
	}
	return config, true
}

func writeConfig(w http.ResponseWriter, config *classes.SpamClasses, user, request string) bool {

	err := logConfig(w, config, "writeConfig", user, request)
	if err != nil {
		msg := fmt.Sprintf("writeConfig: logConfig failed: %v", err)
		fail(w, user, request, msg, http.StatusInternalServerError)
		return false
	}

	err = config.Write(configFile)
	if err != nil {
		fail(w, user, request, "configuration write failed", http.StatusInternalServerError)
		return false
	}
	return true
}

func sendClasses(w http.ResponseWriter, config *classes.SpamClasses, address, request string) {
	response := ClassesResponse{}
	response.User = address
	response.Request = request
	response.Success = true
	response.Message = fmt.Sprintf("%s spam classes", address)
	response.Classes = config.GetClasses(address)
	succeed(w, response.Message, &response)
}

func handleGetClass(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	scoreParam := r.PathValue("score")
	requestString := fmt.Sprintf("classify %v", scoreParam)
	if Verbose {
		log.Printf("GET address=%s score=%s\n", address, scoreParam)
	}
	score, err := strconv.ParseFloat(scoreParam, 32)
	if err != nil {
		fail(w, address, requestString, "score conversion failed", http.StatusBadRequest)
		return
	}

	config, ok := readConfig(w, address, requestString)
	if ok {
		var response ClassResponse
		response.User = address
		response.Request = requestString
		response.Success = true
		response.Class = config.GetClass([]string{address}, float32(score))
		response.Message = fmt.Sprintf("%v", response.Class)
		succeed(w, response.Message, &response)
	}
}

func handleGetClasses(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	requestString := "get classes"
	if Verbose {
		log.Printf("GET address=%s\n", address)
	}
	config, ok := readConfig(w, address, requestString)
	if ok {
		sendClasses(w, config, address, requestString)
	}
}

func handlePostClasses(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	type PostClassesRequest struct {
		Address string
		Classes []classes.SpamClass
	}
	var request PostClassesRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "post classes", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	requestString := "post classes"
	if Verbose {
		log.Printf("POST address=%s classes=%v\n", request.Address, request.Classes)
	}
	config, ok := readConfig(w, request.Address, requestString)
	if !ok {
		fail(w, "system", "post classes", "readConfig failed", http.StatusBadRequest)
		return
	}
	if len(request.Classes) == 0 {
		request.Classes = config.GetClasses("default")
	}
	config.SetClasses(request.Address, request.Classes)
	if writeConfig(w, config, request.Address, requestString) {
		sendClasses(w, config, request.Address, requestString)
	}
}

func handlePutClassThreshold(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	name := r.PathValue("name")
	threshold := r.PathValue("threshold")
	requestString := fmt.Sprintf("set class %s threshold to %v", name, threshold)
	if Verbose {
		log.Printf("PUT address=%s name=%s threshold=%s\n", address, name, threshold)
	}
	score, err := strconv.ParseFloat(threshold, 32)
	if err != nil {
		fail(w, address, requestString, "threshold conversion failed", http.StatusBadRequest)
		return
	}
	config, ok := readConfig(w, address, requestString)
	if !ok {
		return
	}
	config.SetThreshold(address, name, float32(score))
	if writeConfig(w, config, address, requestString) {
		sendClasses(w, config, address, requestString)
	}
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	requestString := "delete user"
	if Verbose {
		log.Printf("DELETE (user) address=%s\n", address)
	}
	config, ok := readConfig(w, address, requestString)
	if !ok {
		return
	}
	config.DeleteClasses(address)
	if writeConfig(w, config, address, requestString) {
		message := "user deleted"
		succeed(w, message, &api.Response{User: address, Request: requestString, Success: true, Message: message})
	}
}

func handleDeleteClass(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	name := r.PathValue("name")
	requestString := fmt.Sprintf("delete class %s", name)
	if Verbose {
		log.Printf("DELETE (class) address=%s name=%s\n", address, name)
	}
	config, ok := readConfig(w, address, requestString)
	if !ok {
		return
	}
	config.GetClasses(address)
	config.DeleteClass(address, name)
	if writeConfig(w, config, address, requestString) {
		sendClasses(w, config, address, requestString)
	}
}

func handleListBooks(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	user := r.PathValue("user")
	requestString := "list books"
	if Verbose {
		log.Printf("GetBooks: user=%s\n", user)
	}

	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.GetBooks(user)
	if err != nil {
		fail(w, user, requestString, fmt.Sprintf("api GetBooks failed: %v", err), http.StatusInternalServerError)
		return
	}

	if Verbose {
		log.Printf("response: %+v\n", response)
	}
	response.User = user
	succeed(w, response.Message, &response)
}

func handleGetAccounts(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	requestString := "get accounts"
	if Verbose {
		log.Printf("GetAccounts\n")
	}

	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.GetAccounts()
	if err != nil {
		fail(w, "system", requestString, fmt.Sprintf("api GetAccounts failed: %v", err), http.StatusInternalServerError)
		return
	}

	if Verbose {
		log.Printf("response: %+v\n", response)
	}
	succeed(w, response.Message, &response)
}

func handleGetUserDump(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	user := r.PathValue("user")
	requestString := fmt.Sprintf("dump user %s", user)
	if Verbose {
		log.Printf("GetUserDump user=%s\n", user)
	}

	mab, ok := MAB(w)
	if !ok {
		return
	}

	apiResponse, err := mab.Dump(user)
	if err != nil {
		fail(w, "system", requestString, fmt.Sprintf("api Dump(%s) failed: %v", user, err), http.StatusInternalServerError)
		return
	}

	if Verbose {
		log.Printf("UserDump API Response: %+v\n", apiResponse)
	}

	config, ok := readConfig(w, user, requestString)
	if !ok {
		return
	}

	classes := config.GetClasses(user)
	if Verbose {
		log.Printf("UserDump Classes: %+v\n", classes)
	}

	userDump := apiResponse.Dump.Users[user]

	var response DumpResponse
	response.User = user
	response.Request = requestString
	response.Success = true
	response.Message = "userdump"
	response.Books = userDump.Books
	response.Classes = classes
	response.Password = userDump.Password
	succeed(w, response.Message, &response)
}

func handleAddBook(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	type CreateBookRequest struct {
		Username    string
		Bookname    string
		Description string
	}
	var request CreateBookRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "create book", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	if Verbose {
		log.Printf("AddBook: user=%s name=%s description=%s\n", request.Username, request.Bookname, request.Description)
	}
	requestString := fmt.Sprintf("create book %s", request.Bookname)
	response, err := mab.AddBook(request.Username, request.Bookname, request.Description)
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("api.AddBook failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &api.Response{User: request.Username, Request: requestString, Message: response.Message, Success: true})
	return

}

func handleAddUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	type CreateUserRequest struct {
		Username string
		Email    string
		Password string
	}
	var request CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "create user", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	requestString := fmt.Sprintf("create user %s", request.Username)
	mab, ok := MAB(w)
	if !ok {
		return
	}
	if Verbose {
		log.Printf("AddUser: user=%s email=%s, password=XXXXXXXXX\n", request.Username, request.Email)
	}
	response, err := mab.AddUser(request.Username, request.Email, "")
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("api.AddBook failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &api.Response{User: request.Username, Request: requestString, Message: response.Message, Success: true})
	return

}

func handlePostRestore(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	type RestoreRequest struct {
		Username string
		Dump     api.ConfigDump
	}
	var request RestoreRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "restore user", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	requestString := fmt.Sprintf("restore user %s", request.Username)
	mab, ok := MAB(w)
	if !ok {
		return
	}
	if Verbose {
		log.Printf("Restore: dump=%+v user=%s\n", request.Dump, request.Username)
	}

	_, err = mab.DeleteUser(request.Username)
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("api.DeleteUser failed: %v", err), http.StatusBadRequest)
	}

	response, err := mab.Restore(&request.Dump, request.Username)
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("api.Restore failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	response.User = request.Username
	succeed(w, response.Message, &response)
	return

}

func handleDeleteBook(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	if Verbose {
		log.Printf("DeleteBook: username=%s bookname=%s\n", username, bookname)
	}
	requestString := fmt.Sprintf("delete book %s", bookname)
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.DeleteBook(username, bookname)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("api.DeleteBook failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &api.Response{User: username, Request: requestString, Message: response.Message, Success: true})
}

func handleAddAddress(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	type AddAddressRequest struct {
		Username string
		Bookname string
		Address  string
		Name     string
	}
	var request AddAddressRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "add address", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	requestString := fmt.Sprintf("add %s to %s", request.Address, request.Bookname)
	if Verbose {
		log.Printf("AddAddress: username=%s bookname=%s address=%s name=%s\n", request.Username, request.Bookname, request.Address, request.Name)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.AddAddress(nil, request.Username, request.Bookname, request.Address, request.Name)
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("api.AddAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &api.Response{User: request.Username, Request: requestString, Message: response.Message, Success: true})
	return
}

func handleDeleteAddress(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	address := r.PathValue("address")
	requestString := fmt.Sprintf("delete %s from %s", address, bookname)
	if Verbose {
		log.Printf("DeleteAddress: user=%s book=%s address=%s\n", username, bookname, address)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.DeleteAddress(username, bookname, address)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("api.DeleteAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &api.Response{User: username, Request: requestString, Message: response.Message, Success: true})
	return
}

func handleListAddresses(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	requestString := fmt.Sprintf("list %s addresses", bookname)
	if Verbose {
		log.Printf("ListAddresses: user=%s book=%s\n", username, bookname)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.Addresses(nil, username, bookname)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("api.Addresses failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &response)
}

// return list of books containing address
func handleScanAddress(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	address := r.PathValue("address")
	requestString := fmt.Sprintf("scan books for %s", address)
	if Verbose {
		log.Printf("ScanAddress: user=%s address=%s\n", username, address)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	apiResponse, err := mab.ScanAddress(username, address)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("api.ScanAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", apiResponse)
	}
	var response ScanResponse
	response.User = username
	response.Request = requestString
	response.Success = true
	response.Message = apiResponse.Message
	response.Books = make([]string, len(apiResponse.Books))
	for i, book := range apiResponse.Books {
		response.Books[i] = book.BookName
	}
	succeed(w, response.Message, &response)
}

func handlePasswordRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	requestString := "password lookup"
	if Verbose {
		log.Printf("PasswordRequest: user=%s\n", username)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.GetPassword(username)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("api.GetPassword failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	if !response.Success {
		fail(w, username, requestString, response.Message, 404)
		return
	}
	response.User = username
	succeed(w, response.Message, &response)
}

func runServer(addr *string, port *int) {

	listen := fmt.Sprintf("%s:%d", *addr, *port)
	server := http.Server{
		Addr:        listen,
		IdleTimeout: 5 * time.Second,
	}

	http.HandleFunc("GET /filterctl/classes/{address}/", handleGetClasses)
	http.HandleFunc("POST /filterctl/classes/", handlePostClasses)
	http.HandleFunc("GET /filterctl/class/{address}/{score}/", handleGetClass)
	http.HandleFunc("PUT /filterctl/classes/{address}/{name}/{threshold}/", handlePutClassThreshold)
	http.HandleFunc("DELETE /filterctl/classes/{address}/", handleDeleteUser)
	http.HandleFunc("DELETE /filterctl/classes/{address}/{name}/", handleDeleteClass)
	http.HandleFunc("GET /filterctl/books/{user}/", handleListBooks)
	http.HandleFunc("GET /filterctl/passwd/{user}/", handlePasswordRequest)
	http.HandleFunc("GET /filterctl/addresses/{user}/{book}/", handleListAddresses)
	http.HandleFunc("GET /filterctl/scan/{user}/{address}/", handleScanAddress)
	http.HandleFunc("POST /filterctl/book/", handleAddBook)
	http.HandleFunc("POST /filterctl/address/", handleAddAddress)
	http.HandleFunc("POST /filterctl/user/", handleAddUser)
	http.HandleFunc("POST /filterctl/accounts/", handleGetAccounts)
	http.HandleFunc("POST /filterctl/restore/", handlePostRestore)
	http.HandleFunc("GET /filterctl/dump/{user}/", handleGetUserDump)
	http.HandleFunc("DELETE /filterctl/book/{user}/{book}/", handleDeleteBook)
	http.HandleFunc("DELETE /filterctl/address/{user}/{book}/{address}/", handleDeleteAddress)

	go func() {
		mode := "daemon"
		if Debug {
			mode = "debug"
		}
		log.Printf("listening on %s in %s mode\n", listen, mode)
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalln("ListenAndServe failed: ", err)
		}
	}()

	<-shutdown

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), SHUTDOWN_TIMEOUT*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		log.Fatalln("Server Shutdown failed: ", err)
	}
	log.Println("shutdown complete")
}

func stopHandler(sig os.Signal) error {
	log.Println("received stop signal")
	shutdown <- struct{}{}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("received reload signal")
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1", "listen address")
	port := flag.Int("port", defaultPort, "listen port")
	debugFlag := flag.Bool("debug", false, "run in foreground mode")
	initFlag := flag.Bool("init", false, "initialize config file and exit")
	verboseFlag := flag.Bool("verbose", false, "verbose mode")
	configFileFlag := flag.String("config", defaultConfigFile, "rspamd class config file")
	logFileFlag := flag.String("logfile", defaultLogFile, "log file full pathname")
	versionFlag := flag.Bool("version", false, "output version")
	insecureFlag := flag.Bool("insecure", false, "skip client certificate validation")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s v%s (api v%s)\n", os.Args[0], Version, api.Version)
		os.Exit(0)
	}

	configFile = *configFileFlag
	Verbose = *verboseFlag
	Debug = *debugFlag
	InsecureSkipClientCertificateValidation = *insecureFlag

	if *initFlag {
		_, err := os.Stat(configFile)
		if err == nil {
			log.Fatalf("refusing init: file %s exists", configFile)
		} else if os.IsNotExist(err) {
			config, err := classes.New("")
			if err != nil {
				log.Fatalln("failure creating classes:", err)
			}
			err = config.Write(configFile)
			if err != nil {
				log.Fatalln("failure writing config file:", err)
			}
			fmt.Printf("config written: %s\n", configFile)
			os.Exit(0)
		} else {
			log.Fatalf("failure checking file: %v", err)
		}
	}

	var rLimit unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatalf("failed getting resource limits: %v", err)
	}

	log.Printf("%s v%s rspamd_classes=v%s mabctl_api=v%s, uid=%d gid=%d rlimit.files=%v started as PID %d\n", serverName, Version, classes.Version, api.Version, os.Getuid(), os.Getgid(), rLimit, os.Getpid())

	if InsecureSkipClientCertificateValidation {
		log.Printf("WARNING: client certificate validation disabled\n")
	}
	viper.SetConfigFile("/etc/mabctl/config.yaml")

	err = viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading /etc/mabctl/config: %v", err)
	}
	if Verbose {
		viper.Set("verbose", true)
		log.Printf("classes config: %s\n", configFile)
		log.Printf("viper config: %s\n", viper.ConfigFileUsed())
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed reading my hostname: %v", err)
	}
	viper.SetDefault("hostname", hostname)

	if !*debugFlag {
		daemonize(logFileFlag, addr, port)
		os.Exit(0)
	}
	go runServer(addr, port)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	<-sigs
	shutdown <- struct{}{}
	os.Exit(0)
}

func daemonize(logFilename, addr *string, port *int) {

	daemon.AddCommand(daemon.StringFlag(signalFlag, "stop"), syscall.SIGTERM, stopHandler)
	daemon.AddCommand(daemon.StringFlag(signalFlag, "reload"), syscall.SIGHUP, reloadHandler)

	ctx := &daemon.Context{
		LogFileName: *logFilename,
		LogFilePerm: 0600,
		WorkDir:     "/",
		Umask:       007,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := ctx.Search()
		if err != nil {
			log.Fatalln("Unable to signal daemon: ", err)
		}
		daemon.SendCommands(d)
		return
	}

	child, err := ctx.Reborn()
	if err != nil {
		log.Fatalln("Fork failed: ", err)
	}

	if child != nil {
		return
	}
	defer ctx.Release()

	go runServer(addr, port)

	err = daemon.ServeSignals()
	if err != nil {
		log.Fatalln("Error: ServeSignals: ", err)
	}
}
