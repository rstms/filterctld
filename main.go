package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rstms/rspamd-classes/classes"
	"github.com/sevlyar/go-daemon"
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
const Version = "0.2.11"

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
	Classes []classes.SpamClass
}

func fail(w http.ResponseWriter, message string, status int) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{false, message, []classes.SpamClass{}})
}

func succeed(w http.ResponseWriter, message string, status int, result []classes.SpamClass) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{true, message, result})
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
	result := config.GetClasses(address)
	message := fmt.Sprintf("%s spam classes", address)
	succeed(w, message, http.StatusOK, result)
}

func handleGetClass(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	scoreParam := r.PathValue("score")
	log.Printf("GET address=%s score=%s\n", address, scoreParam)
	score, err := strconv.ParseFloat(scoreParam, 32)
	if err != nil {
		fail(w, "score conversion failed", http.StatusBadRequest)
		return
	}
	config, ok := readConfig(w)
	if ok {
		class := config.GetClass([]string{address}, float32(score))
		succeed(w, class, http.StatusOK, []classes.SpamClass{{class, float32(score)}})
	}
}

func handleGetClasses(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	log.Printf("GET address=%s\n", address)
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
	log.Printf("PUT address=%s name=%s threshold=%s\n", address, name, threshold)
	score, err := strconv.ParseFloat(threshold, 32)
	if err != nil {
		fail(w, "threshold conversion failed", http.StatusBadRequest)
		return
	}
	config, ok := readConfig(w)
	if ok {
		config.SetThreshold(address, name, float32(score))
		if writeConfig(w, config) {
			sendClasses(w, config, address)
		}
	}
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	log.Printf("DELETE (user) address=%s\n", address)
	config, ok := readConfig(w)
	if ok {
		config.DeleteClasses(address)
		if writeConfig(w, config) {
			result := []classes.SpamClass{}
			succeed(w, "deleted", http.StatusOK, result)
		}
	}
}

func handleDeleteClass(w http.ResponseWriter, r *http.Request) {
	if !checkClientCert(w, r) {
		return
	}
	address := r.PathValue("address")
	name := r.PathValue("name")
	log.Printf("DELETE (class) address=%s name=%s\n", address, name)
	config, ok := readConfig(w)
	if ok {
		config.GetClasses(address)
		config.DeleteClass(address, name)
		if writeConfig(w, config) {
			sendClasses(w, config, address)
		}
	}
}

func runServer(addr *string, port *int) {

	listen := fmt.Sprintf("%s:%d", *addr, *port)
	server := http.Server{
		Addr: listen,
	}

	http.HandleFunc("GET /filterctl/classes/{address}", handleGetClasses)
	http.HandleFunc("GET /filterctl/class/{address}/{score}", handleGetClass)
	http.HandleFunc("PUT /filterctl/classes/{address}/{name}/{threshold}", handlePutClassThreshold)
	http.HandleFunc("DELETE /filterctl/classes/{address}", handleDeleteUser)
	http.HandleFunc("DELETE /filterctl/classes/{address}/{name}", handleDeleteClass)

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
