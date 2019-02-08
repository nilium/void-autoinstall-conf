package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	gziphandler "github.com/NYTimes/gziphandler"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/sys/unix"
)

var validators = map[string]Validator{
	"disk":              Validators{Nonempty, IsAbsPath},
	"bootpartitionsize": MustValidateRegexp(`^[1-9]\d*[KMGTPEZY]$`),
	"swapsize":          PositiveInteger,
	"xbpsrepository":    Validators{Nonempty, PathOrHTTP},
	"pkgs":              Pass,
	"username": Validators{
		Nonempty,
		MaxLength(32),
		MustValidateRegexp(`^[_a-z][-_a-z0-9]*[$]?$`),
	},
	"password":   Nonempty,
	"timezone":   Nonempty,
	"keymap":     Nonempty,
	"libclocale": Nonempty,
	"hostname": Validators{
		Nonempty,
		MustValidateRegexp(`^(?i:(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9]?)?\.)*(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9]?)?))$`),
	},
	"end_action": Choice{
		// func not currently permitted because I don't want to deal with checking it
		"reboot",
		"script",
		"shutdown",
	},
	"end_script": HTTPOrFileURL,
}

var permittedKeys = []string{
	"disk",
	"bootpartitionsize",
	"swapsize",
	"xbpsrepository",
	"pkgs",
	"username",
	"password",
	"timezone",
	"keymap",
	"libclocale",
	"hostname",
	"end_action",
	"end_script",
}

func main() {
	ec := 0
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
		os.Exit(ec)
	}()
	exit := func(status int) {
		ec = status
		runtime.Goexit()
	}

	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile | log.Lmicroseconds)

	network := flag.String("N", "tcp", "listen `network` (tcp, unix)")
	listen := flag.String("L", "127.0.0.1:8096", "listen `address`")
	basePath := flag.String("p", "/autoinstall.cfg", "`path` to serve from")
	logAccess := flag.Bool("a", false, "log access")
	shutdownTimeout := flag.Duration("st", time.Second*10, "shutdown `timeout`")
	flag.Parse()

	// Check server path
	switch basePath := *basePath; {
	case strings.IndexByte(basePath, ':') != -1:
		log.Fatalf("path (%q) may not contain colons (':')", basePath)
	case !path.IsAbs(basePath):
		log.Fatalf("path (%q) must be absolute", basePath)
	}

	// Create listener
	listener, err := net.Listen(*network, *listen)
	if err != nil {
		log.Fatalf("Unable to listen on %s(%s): %v", *network, *listen, err)
	}
	defer listener.Close()

	log.Printf("listening on %v", listener.Addr())

	// Create server
	sv := createServer(*basePath, *logAccess)

	// Shut down server
	go func() {
		defer sv.Close() // Non-graceful shutdown

		// Wait to exit
		note := <-waitForSignal(os.Interrupt, unix.SIGINT)
		log.Printf("received %v signal; exiting", note)

		// Try to shut down gracefully
		if *shutdownTimeout > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
			defer cancel()
			sv.Shutdown(ctx) // ignore error
		}
	}()

	// Serve
	if err := sv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		exit(1)
	}
}

func createServer(basePath string, logAccess bool) *http.Server {
	mux := httprouter.New()
	mux.GET(basePath, serveConfig)

	var handler http.Handler = gziphandler.GzipHandler(mux)

	if logAccess {
		handler = AccessLog(handler)
	}

	return &http.Server{
		Handler: handler,
	}
}

func waitForSignal(signals ...os.Signal) <-chan os.Signal {
	out := make(chan os.Signal, 1) // Output channel
	go func() {
		sig := make(chan os.Signal, 1) // Buffer
		signal.Notify(sig, signals...)
		defer signal.Stop(sig)
		out <- (<-sig)
		close(out)
	}()
	return out
}

const prefix = "#!/bin/sh\n"

var shQuoteReplacer = strings.NewReplacer(
	"`", "\\`",
	`"`, `\"`,
	`$`, `\$`,
	`\`, `\\`,
)

func serveConfig(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "text/plain")

	query := req.URL.Query()

	const minBufferSize = 600
	buf := bytes.NewBuffer(make([]byte, 0, minBufferSize))
	buf.WriteString(prefix)

	if user, password, ok := req.BasicAuth(); ok {
		if user != "" {
			query.Add("username", user)
		}
		if password != "" {
			query.Add("password", password)
		}
	}

	for _, k := range permittedKeys {
		vals, ok := query[k]
		if !ok {
			continue
		}
		val := strings.Join(vals, " ")

		if validator := validators[k]; validator != nil {
			err := validator.Check(val)
			if err != nil {
				msg := fmt.Sprintf("%s: %v", k, err)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}
		}

		buf.WriteString(k)
		buf.WriteString(`="`)
		shQuoteReplacer.WriteString(buf, val)
		buf.WriteString("\"\n")
	}

	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	buf.WriteTo(w)
}
