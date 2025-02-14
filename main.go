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
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const serverName = "filterctld"
const defaultConfigFile = "/etc/mail/filter_rspamd_classes.json"
const defaultLogFile = "/var/log/filterctld.log"
const defaultPort = 2016
const SHUTDOWN_TIMEOUT = 5
const Version = "0.3.1"

var Verbose bool
var Debug bool

var configFile string

var (
	signalFlag = flag.String("s", "", `send signal:
    stop - shutdown
    reload - reload config
    `)
	shutdown = make(chan struct{})
	reload   = make(chan struct{})
)

type Response struct {
	Success bool
	Message string
}

type ClassesResponse struct {
	Response
	Classes []classes.SpamClass
}

type ClassResponse struct {
	Response
	Class string
}

type BooksResponse struct {
	Response
	Books []string
}

type AddressesResponse struct {
	Response
	Addresses []string
}

type PasswordResponse struct {
	Response
	Password string
}

func MAB(w http.ResponseWriter) (*api.Controller, bool) {
	api, err := api.NewAddressBookController()
	if err != nil {
		fail(w, fmt.Sprintf("api init failed: %v", err), http.StatusInternalServerError)
		return nil, false
	}
	return api, true
}

func fail(w http.ResponseWriter, message string, status int) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{false, message})
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
	if Debug {
		return true
	}
	usernameHeader, ok := r.Header["X-Client-Cert-Dn"]
	if !ok {
		fail(w, "missing client cert DN", http.StatusBadRequest)
		return false
	}
	if Verbose {
		log.Printf("client cert dn: %s\n", usernameHeader[0])
	}
	if usernameHeader[0] != "CN=filterctl" {
		fail(w, fmt.Sprintf("client cert (%s) != filterctl", usernameHeader[0]), http.StatusBadRequest)
		return false
	}
	return true
}

func readConfig(w http.ResponseWriter) (*classes.SpamClasses, bool) {
	config, err := classes.New(configFile)
	if err != nil {
		fail(w, "configuration read failed", http.StatusInternalServerError)
		return nil, false
	}
	return config, true
}

func writeConfig(w http.ResponseWriter, config *classes.SpamClasses) bool {
	err := config.Write(configFile)
	if err != nil {
		fail(w, "configuration write failed", http.StatusInternalServerError)
		return false
	}
	return true
}

func sendClasses(w http.ResponseWriter, config *classes.SpamClasses, address string) {
	response := ClassesResponse{}
	response.Success = true
	response.Message = fmt.Sprintf("%s spam classes", address)
	response.Classes = config.GetClasses(address)
	succeed(w, response.Message, &response)
}

func handleGetClass(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	scoreParam := r.PathValue("score")
	if Verbose {
		log.Printf("GET address=%s score=%s\n", address, scoreParam)
	}
	score, err := strconv.ParseFloat(scoreParam, 32)
	if err != nil {
		fail(w, "score conversion failed", http.StatusBadRequest)
		return
	}
	config, ok := readConfig(w)
	if ok {
		var response ClassResponse
		response.Success = true
		response.Class = config.GetClass([]string{address}, float32(score))
		response.Message = fmt.Sprintf("%v", response.Class)
		succeed(w, response.Message, &response)
	}
}

func handleGetClasses(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	if Verbose {
		log.Printf("GET address=%s\n", address)
	}
	config, ok := readConfig(w)
	if ok {
		sendClasses(w, config, address)
	}
}

func handlePutClassThreshold(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	name := r.PathValue("name")
	threshold := r.PathValue("threshold")
	if Verbose {
		log.Printf("PUT address=%s name=%s threshold=%s\n", address, name, threshold)
	}
	score, err := strconv.ParseFloat(threshold, 32)
	if err != nil {
		fail(w, "threshold conversion failed", http.StatusBadRequest)
		return
	}
	config, ok := readConfig(w)
	if !ok {
		return
	}
	config.SetThreshold(address, name, float32(score))
	if writeConfig(w, config) {
		sendClasses(w, config, address)
	}
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	if Verbose {
		log.Printf("DELETE (user) address=%s\n", address)
	}
	config, ok := readConfig(w)
	if !ok {
		return
	}
	config.DeleteClasses(address)
	if writeConfig(w, config) {
		message := "user deleted"
		succeed(w, message, &Response{Success: true, Message: message})
	}
}

func handleDeleteClass(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	name := r.PathValue("name")
	if Verbose {
		log.Printf("DELETE (class) address=%s name=%s\n", address, name)
	}
	config, ok := readConfig(w)
	if !ok {
		return
	}
	config.GetClasses(address)
	config.DeleteClass(address, name)
	if writeConfig(w, config) {
		sendClasses(w, config, address)
	}
}

func handleListBooks(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	user := r.PathValue("user")
	if Verbose {
		log.Printf("GetBooks: user=%s\n", user)
	}

	mab, ok := MAB(w)
	if !ok {
		return
	}
	apiResponse, err := mab.GetBooks(user)
	if err != nil {
		fail(w, fmt.Sprintf("api GetBooks failed: %v", err), http.StatusInternalServerError)
		return
	}

	if Verbose {
		log.Printf("response: %+v\n", apiResponse)
	}
	var response BooksResponse
	response.Success = true
	response.Message = apiResponse.Message
	response.Books = make([]string, len(apiResponse.Books))
	for i, book := range apiResponse.Books {
		if Verbose {
			log.Printf("book: %+v\n", book)
		}
		response.Books[i] = book.BookName
	}
	succeed(w, response.Message, &response)
}

func handleAddBook(w http.ResponseWriter, r *http.Request) {
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
		fail(w, fmt.Sprintf("failed encoding request: %v", err), http.StatusBadRequest)
		return
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	if Verbose {
		log.Printf("AddBook: user=%s name=%s description=%s\n", request.Username, request.Bookname, request.Description)
	}
	response, err := mab.AddBook(request.Username, request.Bookname, request.Description)
	if err != nil {
		fail(w, fmt.Sprintf("api.AddBook failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &Response{Message: response.Message, Success: true})
	return

}

func handleDeleteBook(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	if Verbose {
		log.Printf("DeleteBook: username=%s bookname=%s\n", username, bookname)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.DeleteBook(username, bookname)
	if err != nil {
		fail(w, fmt.Sprintf("api.DeleteBook failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &Response{Message: response.Message, Success: true})
}

func handleAddAddress(w http.ResponseWriter, r *http.Request) {
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
		fail(w, fmt.Sprintf("failed encoding request: %v", err), http.StatusBadRequest)
		return
	}
	if Verbose {
		log.Printf("AddAddress: username=%s bookname=%s address=%s name=%s\n", request.Username, request.Bookname, request.Address, request.Name)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.AddAddress(request.Username, request.Bookname, request.Address, request.Name)
	if err != nil {
		fail(w, fmt.Sprintf("api.AddAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &Response{Message: response.Message, Success: true})
	return
}

func handleDeleteAddress(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	address := r.PathValue("address")
	if Verbose {
		log.Printf("DeleteAddress: user=%s book=%s address=%s\n", username, bookname, address)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	response, err := mab.DeleteAddress(username, bookname, address)
	if err != nil {
		fail(w, fmt.Sprintf("api.DeleteAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", response)
	}
	succeed(w, response.Message, &Response{Message: response.Message, Success: true})
	return
}

func handleListAddresses(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	bookname := r.PathValue("book")
	if Verbose {
		log.Printf("ListAddresses: user=%s book=%s\n", username, bookname)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	apiResponse, err := mab.Addresses(username, bookname)
	if err != nil {
		fail(w, fmt.Sprintf("api.Addresses failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", apiResponse)
	}
	var response AddressesResponse
	response.Success = true
	response.Message = apiResponse.Message
	response.Addresses = make([]string, len(apiResponse.Addresses))
	for i, addr := range apiResponse.Addresses {
		response.Addresses[i] = fmt.Sprintf("%v", addr)
	}
	succeed(w, response.Message, &response)
}

// return list of books containing address
func handleScanAddress(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	address := r.PathValue("address")
	if Verbose {
		log.Printf("ScanAddress: user=%s address=%s\n", username, address)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	apiResponse, err := mab.ScanAddress(username, address)
	if err != nil {
		fail(w, fmt.Sprintf("api.ScanAddress failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", apiResponse)
	}
	var response BooksResponse
	response.Success = true
	response.Message = apiResponse.Message
	response.Books = make([]string, len(apiResponse.Books))
	for i, book := range apiResponse.Books {
		response.Books[i] = book.BookName
	}
	succeed(w, response.Message, &response)
}

func handlePasswordRequest(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	username := r.PathValue("user")
	if Verbose {
		log.Printf("PasswordRequest: user=%s\n", username)
	}
	mab, ok := MAB(w)
	if !ok {
		return
	}
	apiResponse, err := mab.GetPassword(username)
	if err != nil {
		fail(w, fmt.Sprintf("api.GetPassword failed: %v", err), http.StatusInternalServerError)
		return
	}
	if Verbose {
		log.Printf("response: %v\n", apiResponse)
	}
	var response PasswordResponse
	response.Success = true
	response.Message = fmt.Sprintf("%s password", username)
	response.Password = apiResponse
	succeed(w, response.Message, &response)
}

func runServer(addr *string, port *int) {

	listen := fmt.Sprintf("%s:%d", *addr, *port)
	server := http.Server{
		Addr: listen,
	}

	http.HandleFunc("GET /filterctl/classes/{address}/", handleGetClasses)
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
	http.HandleFunc("DELETE /filterctl/book/{user}/{book}/", handleDeleteBook)
	http.HandleFunc("DELETE /filterctl/book/{user}/{book}/{address}/", handleDeleteAddress)

	go func() {
		log.Printf("%s v%s rspamd_classes=v%s uid=%d gid=%d started as PID %d listening on %s\n", serverName, Version, classes.Version, os.Getuid(), os.Getgid(), os.Getpid(), listen)
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

	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s v%s\n", os.Args[0], Version)
		os.Exit(0)
	}

	configFile = *configFileFlag
	Verbose = *verboseFlag
	Debug = *debugFlag

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
			log.Fatalf("failure checking file:", err)
		}
	}

	viper.SetConfigType("yaml")
	viper.SetConfigFile("/etc/mabctl/config")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading /etc/mabctl/config: %v", err)
	}
	if Verbose {
		log.Printf("config read from %s\n", viper.ConfigFileUsed())
	}

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
