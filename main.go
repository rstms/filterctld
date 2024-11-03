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
const defaultPort = 2016
const SHUTDOWN_TIMEOUT = 5
const Version = "0.0.3"

var configFile = "/home/mkrueger/classes.json"

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
	result, ok := config.Classes[address]
	if ok {
		message := fmt.Sprintf("%s spam classes", address)
		succeed(w, message, http.StatusOK, result)
		return
	}
	fail(w, "address not found", http.StatusNotFound)
}

func handleGetClasses(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	log.Printf("GET address=%s\n", address)
	config, ok := readConfig(w)
	if ok {
		sendClasses(w, config, address)
	}
}

func handlePutClassThreshold(w http.ResponseWriter, r *http.Request) {
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

func handleDeleteClasses(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	log.Printf("DELETE address=%s\n", address)
	config, ok := readConfig(w)
	if ok {
		_, ok := config.Classes[address]
		if ok {
			config.Classes[address] = nil
		}
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
	http.HandleFunc("GET /classes/{address}", handleGetClasses)
	http.HandleFunc("PUT /classes/{address}/{name}/{threshold}", handlePutClassThreshold)
	http.HandleFunc("DELETE /classes/{address}", handleDeleteClasses)

	go func() {
		log.Printf("%s v%s rspamd_classes=v%s started as PID %d listening on %s\n", serverName, Version, classes.Version, os.Getpid(), listen)
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
	flag.Parse()

	if !*debugFlag {
		daemonize(addr, port)
		os.Exit(0)
	}
	go runServer(addr, port)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	<-sigs
	shutdown <- struct{}{}
	os.Exit(0)
}

func daemonize(addr *string, port *int) {

	daemon.AddCommand(daemon.StringFlag(signalFlag, "stop"), syscall.SIGTERM, stopHandler)
	daemon.AddCommand(daemon.StringFlag(signalFlag, "reload"), syscall.SIGHUP, reloadHandler)

	ctx := &daemon.Context{
		LogFileName: "/var/log/filterctld.log",
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
