package main

import (
	"bufio"
	"fmt"
	"github.com/rstms/mabctl/api"
	"github.com/spf13/viper"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const THRESHOLD = 70

var addrPattern = regexp.MustCompile(`^[^[]*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].*`)

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

func transformPath(user, folder string) string {
	var dir string
	if folder == "/INBOX" {
		dir = fmt.Sprintf("/home/%s/Maildir/cur", user)
	} else {
		folder = strings.ReplaceAll(folder, "/", ".")
		dir = fmt.Sprintf("/home/%s/Maildir/%s/cur", user, folder)
	}
	return dir
}

func scanMessageFiles(dir string, messageIds []string) ([]string, error) {
	files := []string{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{}, fmt.Errorf("failed reading directory: %v", err)
	}
	if len(messageIds) == 0 {
		for _, entry := range entries {
			if !entry.IsDir() {
				files = append(files, path.Join(dir, entry.Name()))
			}
		}
	} else {
		idMap := make(map[string]string)
		total := len(messageIds)
		count := 0
		for _, id := range messageIds {
			idMap[id] = "."
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				file := path.Join(dir, entry.Name())
				fileId, err := getMessageId(file)
				if err != nil {
					return []string{}, err
				}
				_, found := idMap[fileId]
				if found {
					idMap[fileId] = file
					count += 1
				}
			}
			if count == total {
				break
			}
		}
		for _, file := range idMap {
			files = append(files, file)
		}
	}
	return files, nil
}

func getMessageId(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed opening file: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Message-Id:") {
			_, id, _ := strings.Cut(line, ":")
			return strings.TrimSpace(id), nil
		}
	}
	err = scanner.Err()
	if err != nil {
		return "", fmt.Errorf("failed reading message file: %v", err)
	}
	return "", fmt.Errorf("Message-Id not found")
}

func Rescan(username, folder string, messageIds []string) (int, error) {
	messages := []string{}
	var count int

	user, _, found := strings.Cut(username, "@")
	if !found {
		return 0, fmt.Errorf("failed parsing username")
	}
	dir := transformPath(user, folder)

	messages, err := scanMessageFiles(dir, messageIds)
	if err != nil {
		return 0, fmt.Errorf("failed scanning message files")
	}

	for _, message := range messages {
		err := RescanMessage(username, message)
		if err != nil {
			return 0, err
		}
		count += 1
	}
	return count, nil
}

func RescanMessage(username, file string) error {

	rspamd, err := NewAPIClient()
	if err != nil {
		return err
	}
	//response := make(map[string]any)
	var response RspamdResponse
	message, err := os.ReadFile(file)
	text, err := rspamd.Post("/rspamc/checkv2", &message, &response)
	if err != nil {
		return err
	}

	if viper.GetBool("verbose") {
		fmt.Printf("---BEGIN---\n%s\n---END---\n\n", text)
		fmt.Printf("%+v\n", response)

		for name := range response.Milter.RemoveHeaders {
			fmt.Printf("remove: %s\n", name)
		}

		for name, header := range response.Milter.AddHeaders {
			if name != "X-Spamd-Result" && name != "X-Spam-Status" {
				fmt.Printf("add: %s %s\n", name, header.Value)
			}
		}
	}

	symbols := []Symbol{}
	for _, symbol := range response.Symbols {
		symbols = append(symbols, symbol)
	}

	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Name < symbols[j].Name
	})

	headers := make(map[string]string)

	// generate X-Spam-Status header
	spamStatus := fmt.Sprintf("%s required=%.3f", response.Milter.AddHeaders["X-Spam-Status"].Value, response.Required)
	line := "\ttests["
	delim := ""
	for _, symbol := range symbols {
		section := fmt.Sprintf("%s=%.3f", symbol.Name, symbol.Score)
		if len(line)+len(section) > THRESHOLD {
			spamStatus += "\n" + line
			line = "\t"
			delim = ""
		}
		line += delim + section
		delim = ", "
	}
	spamStatus += "]"

	lines := strings.Split(string(message), "\n")

	headers["X-Spam-Score"] = fmt.Sprintf("%.3f / %.3f", response.Score, response.Required)

	senderScore, err := getSenderScore(lines)
	if err != nil {
		return err
	}
	headers["X-SenderScore"] = fmt.Sprintf("%d", senderScore)

	mab, err := api.NewAddressBookController()
	if err != nil {
		return fmt.Errorf("failed creating AddressBookController: %v", err)
	}
	fromAddress, toAddress := getAddresses(lines)
	booksResponse, err := mab.ScanAddress(toAddress, fromAddress)
	if err != nil {
		return err
	}
	books := []string{}
	for _, book := range booksResponse.Books {
		books = append(books, book.BookName)
	}

	class, err := GetClass(toAddress, response.Score)
	if err != nil {
		return err
	}
	headers["X-Spam-Class"] = class

	var spamValue string
	if class == "spam" {
		spamValue = "yes"
	} else {
		spamValue = "no"
	}
	headers["X-Spam"] = spamValue

	headers["X-Spam-Status"] = spamStatus
	headers["Authentication-Results"] = response.Milter.AddHeaders["Authentication-Results"].Value

	outfile := file + ".out"

	err = processMessage(outfile, lines, response.Milter.RemoveHeaders, headers, books)
	if err != nil {
		return err
	}
	return nil
}

func processMessage(filename string, lines []string, headersToRemove map[string]int, headersToAdd map[string]string, books []string) error {

	outfile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed opening output file: %v", err)
	}
	defer outfile.Close()

	inHeaders := true
	received := false
	headerBuf := []string{}

	for _, line := range lines {
		if inHeaders {
			// if this is the start of a new header
			if isHeader(line) {
				// if we have a header buffered, send it
				key, err := writeHeader(outfile, headerBuf, headersToRemove)
				if err != nil {
					return err
				}
				if strings.ToLower(key) == "received" {
					// if we just wrote a received header
					if !received {
						// and it is the first one, write out the headers we're adding
						for key, value := range headersToAdd {
							_, err := fmt.Fprintf(outfile, "%s: %s\n", key, value)
							if err != nil {
								return fmt.Errorf("failed writing header: %v", err)
							}
						}
						for _, book := range books {
							_, err := fmt.Fprintf(outfile, "X-Address-Book: %s\n", book)
							if err != nil {
								return fmt.Errorf("failed writing header: %v", err)
							}

						}
					}
					received = true
				}
				// init the buffer with this new header
				headerBuf = []string{line}
			} else {
				if isBlank(line) {
					if !received {
						return fmt.Errorf("no received header found")
					}

					// this is the end of the headers, write the buffered header
					_, err := writeHeader(outfile, headerBuf, headersToRemove)
					// write the blank line ending the header section
					_, err = fmt.Fprintf(outfile, "\n")
					if err != nil {
						return fmt.Errorf("failed writing blank line: %v", err)
					}
					inHeaders = false
				} else {
					// not a header, not a blank, add to the current header buffer
					headerBuf = append(headerBuf, line)
				}
			}
		} else {
			// we're done with the headers, write out every body line
			_, err := fmt.Fprintf(outfile, "%s\n", line)
			if err != nil {
				return fmt.Errorf("failed writing body line: %v", err)
			}
		}
	}

	return nil

}

func writeHeader(outfile *os.File, lines []string, headersToRemove map[string]int) (string, error) {
	if len(lines) == 0 {
		return "", nil
	}
	key := headerKey(lines[0])
	if shouldDelete(key, headersToRemove) {
		return key, nil
	}
	for _, line := range lines {
		_, err := fmt.Fprintf(outfile, "%s\n", line)
		if err != nil {
			return "", fmt.Errorf("failed writing header: %v", err)
		}
	}
	return key, nil
}

func shouldDelete(key string, headersToRemove map[string]int) bool {
	_, remove := headersToRemove[key]
	if remove {
		return true
	}
	return strings.HasPrefix(key, "X-Spam")
}

func headerKey(line string) string {
	fields := strings.Split(line, ":")
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func isHeader(line string) bool {
	if len(line) == 0 {
		return false
	}
	firstRune := []rune(line)[0]
	return !unicode.IsSpace(firstRune)
}

func isBlank(line string) bool {
	return len(strings.TrimSpace(line)) == 0
}

func getSpamClass(score float32) (string, error) {
	return "unknown", nil
}

func getAddresses(lines []string) (string, string) {
	fromAddr := ""
	toAddr := ""
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "Delivered-To:"):
			_, toAddr, _ = strings.Cut(line, ":")
			toAddr = strings.TrimSpace(toAddr)
			break
		case strings.HasPrefix(line, "From:"):
			_, fromAddr, _ = strings.Cut(line, ":")
			fromAddr = strings.TrimSpace(fromAddr)
			break
		case line == "":
			break
		}
	}
	return fromAddr, toAddr
}

func getSenderScore(lines []string) (int, error) {
	var received int
	for _, line := range lines {
		if strings.HasPrefix(line, "Received:") {
			received += 1
			if received > 2 {
				return 0, fmt.Errorf("IP address not found in second Received line")
			}
		}
		//fmt.Printf("SS %d %s\n", received, line)
		if received == 2 {
			match := addrPattern.FindStringSubmatch(line)
			//fmt.Printf("SS match: %v\n", match)
			if len(match) > 1 {
				addr := match[1]
				//fmt.Printf("Received from: %s\n", addr)
				octets := strings.Split(addr, ".")
				lookup := fmt.Sprintf("%s.%s.%s.%s.score.senderscore.com", octets[3], octets[2], octets[1], octets[0])
				//fmt.Printf("Lookup: %s\n", lookup)
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
					fmt.Printf("senderScore for %s is %d\n", addr, score)
				}
				return score, nil
			}
		}
	}
	return 0, fmt.Errorf("failed scan for received IP address")
}
