package main

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"io/fs"
	"log"
	"net"
	"net/mail"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// RFC says 76; but we append a ] after breaking X-Spam-Score
const MAX_HEADER_LENGTH = 75

var addrPattern = regexp.MustCompile(`^[^[]*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].*`)

// these structures decode only what we need from the RSPAMD JSON response
type AddHeader struct {
	Order int
	Value string
}

type MilterMap struct {
	AddHeaders    map[string]AddHeader `json:"add_headers"`
	RemoveHeaders map[string]int       `json:"remove_headers"`
}

type Symbol struct {
	Description string
	MetricScore float32 `json:"metric_score"`
	Name        string
	Options     []string
	Score       float32
}

type RspamdResponse struct {
	Score      float32
	Required   float32 `json:"required_score"`
	Milter     MilterMap
	Urls       []string
	Thresholds map[string]float32
	Symbols    map[string]Symbol
}

type MessageFile struct {
	ID       string
	Info     fs.FileInfo
	Pathname string
}

func transformPath(user, folder string) string {
	var path string
	if folder == "/INBOX" {
		path = fmt.Sprintf("/home/%s/Maildir/cur", user)
	} else {
		mailDir := strings.ReplaceAll(folder, "/", ".")
		path = fmt.Sprintf("/home/%s/Maildir/%s/cur", user, mailDir)
	}
	if viper.GetBool("verbose") {
		log.Printf("transformPath: user=%s folder=%s path=%s\n", user, folder, path)
	}
	return path
}

func scanMessageFiles(dir string, messageIds []string) ([]MessageFile, error) {

	messageFiles := []MessageFile{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return messageFiles, fmt.Errorf("failed reading directory: %v", err)
	}
	if len(messageIds) == 0 {
		// no messsageId list, so just include all files
		for _, entry := range entries {
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return messageFiles, fmt.Errorf("failed reading directory entry: %v", err)
				}
				messageFiles = append(messageFiles, MessageFile{
					Info:     info,
					Pathname: path.Join(dir, entry.Name()),
				})
			}
		}
	} else {
		// messageId list specified, search directory for matching messages
		total := len(messageIds)
		idMap := make(map[string]bool, total)
		for _, mid := range messageIds {
			idMap[mid] = true
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				pathname := path.Join(dir, entry.Name())
				mid, err := getMessageId(pathname)
				if err != nil {
					return messageFiles, err
				}
				if idMap[mid] {
					info, err := entry.Info()
					if err != nil {
						return messageFiles, fmt.Errorf("failed reading directory entry: %v", err)
					}
					messageFiles = append(messageFiles, MessageFile{
						ID:       mid,
						Info:     info,
						Pathname: pathname,
					})
				}
			}
			if len(messageFiles) == total {
				break
			}
		}
	}
	if viper.GetBool("verbose") {
		log.Printf("scanMessageFiles: dir=%s count=%d \n", dir, len(messageFiles))
		for i, messageFile := range messageFiles {
			log.Printf("  [%d] %+v\n", i, messageFile)
		}
	}
	return messageFiles, nil
}

func getMessageId(pathname string) (string, error) {
	file, err := os.Open(pathname)
	if err != nil {
		return "", fmt.Errorf("failed opening file: %v", err)
	}
	defer file.Close()
	message, err := mail.ReadMessage(file)
	mid := message.Header.Get("Message-Id")
	mid = strings.TrimSpace(mid)
	mid = strings.TrimLeft(mid, "<")
	mid = strings.TrimRight(mid, ">")
	mid = strings.TrimSpace(mid)
	if len(mid) == 0 {
		return "", fmt.Errorf("failed parsing Message-Id header")
	}
	return mid, nil
}

func Rescan(userAddress, folder string, messageIds []string) (int, error) {
	var count int

	if viper.GetBool("verbose") {
		log.Printf("Rescan: folder=%s\n", folder)
		for i, mid := range messageIds {
			log.Printf("   [%d] %s\n", i, mid)
		}
	}

	username, _, found := strings.Cut(userAddress, "@")
	if !found {
		return 0, fmt.Errorf("failed parsing userAddress: %s", userAddress)
	}

	path := transformPath(username, folder)

	messageFiles, err := scanMessageFiles(path, messageIds)
	if err != nil {
		return 0, fmt.Errorf("failed scanning message files")
	}

	client, err := NewAPIClient()
	if err != nil {
		return 0, err
	}

	for _, messageFile := range messageFiles {
		err := RescanMessage(client, userAddress, messageFile)
		if err != nil {
			return 0, err
		}
		count += 1
	}
	return count, nil
}

func RescanMessage(client *APIClient, userAddress string, messageFile MessageFile) error {

	var response RspamdResponse
	content, err := os.ReadFile(messageFile.Pathname)
	lines := strings.Split(string(content), "\n")
	message, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed parsing mail message: %v", err)
	}

	if viper.GetBool("verbose") {
		log.Println("---BEGIN RAW HEADERS---")
		for _, line := range lines {
			log.Println(line)
			if len(strings.TrimSpace(line)) == 0 {
				break
			}
		}
		log.Println("---END RAW HEADERS---")

		log.Println("---BEGIN PARSED HEADERS---")
		for key, values := range message.Header {
			for _, value := range values {
				log.Printf("%s: %s\n", key, value)
			}
		}
		log.Println("---END PARSED HEADERS---")
	}

	fromAddr, err := parseHeaderAddr(message, "From")
	if err != nil {
		return err
	}
	rcptToAddr, err := parseHeaderAddr(message, "To")
	if err != nil {
		return err
	}
	deliveredToAddr, err := parseHeaderAddr(message, "Delivered-To")
	if err != nil {
		return err
	}

	senderIP, err := getSenderIP(message)
	if err != nil {
		return err
	}

	requestHeaders := map[string]string{
		"settings":   `{"symbols_disabled": ["DATE_IN_PAST"]}`,
		"IP":         senderIP,
		"From":       fromAddr,
		"Rcpt":       rcptToAddr,
		"Deliver-To": deliveredToAddr,
		"Hostname":   viper.GetString("hostname"),
	}

	_, err = client.Post("/rspamc/checkv2", &content, &response, &requestHeaders)
	if err != nil {
		return err
	}

	if viper.GetBool("verbose") {

		//log.Printf("---BEGIN RESPONSE---\n%s\n---END RESPONSE---\n\n", text)
		//log.Printf("%+v\n", response)

		for name := range response.Milter.RemoveHeaders {
			log.Printf("remove: %s\n", name)
		}

		for name, header := range response.Milter.AddHeaders {
			if name != "X-Spamd-Result" && name != "X-Spam-Status" {
				log.Printf("add: %s %s\n", name, header.Value)
			}
		}
	}

	// delete the headers RSPAMD wants to delete
	deleteKeys := []string{}
	for removeKey, _ := range response.Milter.RemoveHeaders {
		for headerKey, _ := range message.Header {
			if strings.ToLower(removeKey) == strings.ToLower(headerKey) {
				deleteKeys = append(deleteKeys, headerKey)
			}
		}
	}

	for headerKey, _ := range message.Header {
		log.Printf("headerKey: %s\n", headerKey)
		log.Printf(`strings.ToLower(headerKey): %v\n`, strings.ToLower(headerKey))
		log.Printf(`strings.HasPrefix(strings.ToLower(headerKey), "x-spam"): %v\n`, strings.HasPrefix(strings.ToLower(headerKey), "x-spam"))
		if strings.HasPrefix(strings.ToLower(headerKey), "x-spam") {
			deleteKeys = append(deleteKeys, headerKey)
		}
		if strings.HasPrefix(strings.ToLower(headerKey), "x-rspam") {
			deleteKeys = append(deleteKeys, headerKey)
		}
	}
	for _, key := range deleteKeys {
		log.Printf("deleting: %s\n", key)
		delete(message.Header, key)
	}

	skipAddKeys := map[string]bool{
		"X-Rspamd-Pre-Result": true,
		"X-Rspamd-Action":     true,
		"X-Spamd-Bar":         true,
		"X-Spamd-Result":      true,
	}
	// copy the headers RSPAMD wants to add
	for key, header := range response.Milter.AddHeaders {
		if !skipAddKeys[key] {
			message.Header[key] = []string{header.Value}
		}
	}

	symbols := []Symbol{}
	for _, symbol := range response.Symbols {
		symbols = append(symbols, symbol)
	}

	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Name < symbols[j].Name
	})

	// generate new X-Spam-Status header
	spamStatus := fmt.Sprintf("%s required=%.3f\n    tests[", message.Header.Get("X-Spam-Status"), response.Required)
	delim := ""
	for _, symbol := range symbols {
		spamStatus += fmt.Sprintf("%s%s=%.3f", delim, symbol.Name, symbol.Score)
		delim = ", "
	}
	spamStatus += "]"
	message.Header["X-Spam-Status"] = []string{spamStatus}

	message.Header["X-Spam-Score"] = []string{fmt.Sprintf("%.3f / %.3f", response.Score, response.Required)}

	senderScore, err := getSenderScore(senderIP)
	if err != nil {
		return err
	}
	message.Header["X-SenderScore"] = []string{fmt.Sprintf("%d", senderScore)}

	//books, err := getBooks(client, userAddress, &lines)
	books, err := client.ScanAddressBooks(userAddress, fromAddr)
	if err != nil {
		return err
	}
	if len(books) > 0 {
		message.Header["X-Address-Book"] = books
	}

	//class, err := getSpamClass(client, userAddress, response.Score)
	class, err := client.ScanSpamClass(userAddress, response.Score)
	if err != nil {
		return err
	}
	message.Header["X-Spam-Class"] = []string{class}

	var spamValue string
	if class == "spam" {
		spamValue = "yes"
	} else {
		spamValue = "no"
	}
	message.Header["X-Spam"] = []string{spamValue}

	outputPath, err := generateOutputPath(&messageFile)
	if err != nil {
		return err
	}

	if viper.GetBool("verbose") {
		log.Println("---BEGIN CHANGED HEADERS---")
		for key, values := range message.Header {
			for _, value := range values {
				log.Printf("%s: %s\n", key, value)
			}
		}
		log.Println("---END CHANGED HEADERS---")
	}

	err = writeMessage(outputPath, message)
	if err != nil {
		return err
	}
	return nil
}

func parseHeaderAddr(message *mail.Message, key string) (string, error) {
	value := message.Header.Get(key)
	if value == "" {
		return "", fmt.Errorf("header not found: %s", key)
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("failed parsing email addres from header: %v", err)
	}
	return addr.Address, nil
}

func getSenderIP(message *mail.Message) (string, error) {
	received := message.Header["Received"]
	if len(received) < 2 {
		return "", fmt.Errorf("insufficient Received headers")
	}
	match := addrPattern.FindStringSubmatch(received[1])
	if len(match) < 2 {
		return "", fmt.Errorf("Failed parsing IP address from: '%s'", received[1])
	}
	addr := match[1]
	if viper.GetBool("verbose") {
		log.Printf("getSenderIP returning: %s\n", addr)
	}
	return addr, nil
}

func getSenderScore(addr string) (int, error) {
	octets := strings.Split(addr, ".")
	lookup := fmt.Sprintf("%s.%s.%s.%s.score.senderscore.com", octets[3], octets[2], octets[1], octets[0])
	ips, err := net.LookupIP(lookup)
	if err != nil {
		return 0, fmt.Errorf("DNS query failed: %v", err)
	}
	var score int
	for _, ip := range ips {
		ip4 := ip.To4()
		score = int(ip4[3])
	}
	if viper.GetBool("verbose") {
		log.Printf("senderScore for %s is %d\n", addr, score)
	}
	return score, nil
}

// FIXME: this will copy the original to a backup and return the input path
// for now, write all modified files to a rescan subdir sibling to 'cur'
func generateOutputPath(messageFile *MessageFile) (string, error) {
	filePath := path.Dir(messageFile.Pathname)
	fileName := path.Base(messageFile.Pathname)
	parent := path.Dir(filePath)
	dir := path.Base(filePath)
	if dir != "cur" {
		return "", fmt.Errorf("dir not cur: path=%s filename=%s parent=%s dir=%s message=%+v\n", filePath, fileName, parent, dir, *messageFile)
	}
	outPath := path.Join(parent, "rescan", fileName)
	outDir := path.Dir(outPath)
	err := os.MkdirAll(outDir, 0700)
	if err != nil {
		return "", fmt.Errorf("failed creating output path: %v", err)
	}
	if viper.GetBool("verbose") {
		log.Printf("outPath=%s filePath=%s fileName=%s parent=%s dir=%s message=%+v\n", outPath, filePath, fileName, parent, dir, *messageFile)
	}
	return outPath, nil
}

func writeMessage(pathname string, message *mail.Message) error {
	outfile, err := os.Create(pathname)
	if err != nil {
		return fmt.Errorf("failed opening output file: %v", err)
	}
	defer outfile.Close()

	if viper.GetBool("verbose") {
		log.Println("---BEGIN HEADER OUTPUT---")
	}
	for key, values := range message.Header {
		for _, value := range values {
			_, err := fmt.Fprintf(outfile, "%s: %v\n", key, value)
			if err != nil {
				return fmt.Errorf("failed writing header line: %v", err)
			}
		}
	}
	if viper.GetBool("verbose") {
		log.Println("---END HEADER OUTPUT---")
	}
	_, err = fmt.Fprintln(outfile, "")
	if err != nil {
		return fmt.Errorf("failed writing separator: %v", err)
	}
	_, err = io.Copy(outfile, message.Body)
	if err != nil {
		return fmt.Errorf("failed writing body: %v", err)
	}
	return nil
}

/*
func writeHeader(outfile *os.File, key, value string) error {
	line := key + ": "
	delim := ""
	chunks := strings.Split(value, " ")
	for _, chunk := range chunks {
		vlines := strings.Split(line, "\n")
		vlen := len(vlines[len(vlines)-1])
		if vlen+len(delim)+len(chunk) >= MAX_HEADER_LENGTH {
			delim = "\n    "
		}
		line += delim + chunk
		delim = " "
	}

	if viper.GetBool("verbose") {
		log.Printf("%s\n", line)
	}

	_, err := fmt.Fprintf(outfile, "%s\n", line)
	if err != nil {
		return fmt.Errorf("failed writing header line: %v", err)
	}

	return nil
}
*/

//// these functions can be used instead of sending an HTTP request
//// when we are running in the server process on the mailqueue

/*
func getSpamClass(userAddress string, score float32) (string, error) {
	config, err := classes.New(configFile)
	if err != nil {
		return "", err
	}
	class := config.GetClass([]string{userAddress}, float32(score))
	return class, nil
}

func getBooks(userAddress string, lines *[]string) (*[]string, error) {

	mab, err := api.NewAddressBookController()
	if err != nil {
		return nil, fmt.Errorf("failed creating AddressBookController: %v", err)
	}
	booksResponse, err := mab.ScanAddress(userAddress, fromAddress)
	if err != nil {
		return nil, err
	}

	books := []string{}
	for _, book := range booksResponse.Books {
		books = append(books, book.BookName)
	}

	if viper.GetBool("verbose") {
		log.Printf("getBooks: user=%s to=%s from=%s books=%v\n", userAddress, toAddress, fromAddress, books)
	}
	return &books, nil
}
*/
