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

release: build test
	bump && gh release create v$$(cat VERSION) --notes "v$$(cat VERSION)"
