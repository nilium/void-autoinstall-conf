# GO
PACKAGE := go.spiff.io/void-autoinstall-conf
GO_SRC := $(shell go list -f '{{.ImportPath}}{{"\n"}}{{range .Deps}}{{.}}{{"\n"}}{{end}}' $(PACKAGE) | xargs go list -f '{{$$dir := .Dir}}{{range .GoFiles}}{{$$dir}}/{{.}}{{"\n"}}{{end}}')
VENDOR_LICENSES := $(shell ./vendor-licenses -src)

.PHONY: all test go-test clean

all: void-autoinstall-conf NOTICE

test: go-test

NOTICE:
	./vendor-licenses -gen > NOTICE

void-autoinstall-conf: $(GO_SRC)
	go build -mod=vendor -o "$@" -v $(PACKAGE)

go-test:
	go test -v -cover $(PACKAGE)/...

clean:
	$(RM) void-autoinstall-conf NOTICE
