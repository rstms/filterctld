# filter-rspamd-class  makefile

filter = filter-rspamd-class

build: fmt
	fix go build

fmt: go.sum
	fix go fmt . ./...

install: build
	doas install -m 0555 $(filter) /usr/local/libexec/smtpd/$(filter) && doas rcctl restart smtpd

test:
	go test -v 

release: build test
	bump && gh release create v$$(cat VERSION) --notes "v$$(cat VERSION)"

clean:
	go clean 

sterile: clean
	rm -f go.mod go.sum

go.sum: go.mod
	go mod tidy

go.mod:
	go mod init
