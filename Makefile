# filter-rspamd-class  makefile

filter = filter-rspamd-class

build: fmt
	fix go build

fmt:
	fix go fmt . ./...

install: build
	doas install -m 0555 $(filter) /usr/local/libexec/smtpd/$(filter) && doas rcctl restart smtpd

test:
	go test -v 
