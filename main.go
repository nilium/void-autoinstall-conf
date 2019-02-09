package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gziphandler "github.com/NYTimes/gziphandler"
	"github.com/julienschmidt/httprouter"
	"github.com/tv42/zbase32"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
)

var authHash []byte

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

	var (
		minPersistedConfigs = flag.Int("pm", 100, "`min`imum number of persisted configs to retain")
		bootPass            = flag.String("p", "", "boot persistence `password` (may be a bcrypt hash)")
		bootPassCost        = flag.Int("pc", 12, "boot persistence token `cost`")
		network             = flag.String("N", "tcp", "listen `network` (tcp, unix)")
		listen              = flag.String("L", "127.0.0.1:8096", "listen `address`")
		logAccess           = flag.Bool("a", false, "log access")
		shutdownTimeout     = flag.Duration("st", time.Second*10, "shutdown `timeout`")
	)
	flag.Parse()

	if *bootPass == "" {
		*bootPass = os.Getenv("SAVE_PASSWORD")
	}

	// Create persistence hash (if set)
	if pass := []byte(*bootPass); len(pass) == 0 {
	} else if _, err := bcrypt.Cost(pass); err == nil {
		authHash = pass
	} else if authHash, err = bcrypt.GenerateFromPassword(pass, *bootPassCost); err != nil {
		log.Fatalf("Unable to hash password (len=%d cost=%d): %v", len(pass), *bootPassCost, err)
	} else {
		log.Printf("Persistence hash = %q (may be reused)", authHash)
	}

	if len(authHash) > 0 {
		min := *minPersistedConfigs
		go func() {
			for range time.Tick(time.Minute) {
				purgeOldConfigs(min)
			}
		}()
	}

	// Create listener
	listener, err := net.Listen(*network, *listen)
	if err != nil {
		log.Fatalf("Unable to listen on %s(%s): %v", *network, *listen, err)
	}
	defer listener.Close()

	log.Printf("listening on %v", listener.Addr())

	// Create server
	sv := createServer(*logAccess)

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

func createServer(logAccess bool) *http.Server {
	mux := httprouter.New()
	mux.GET("/autoinstall.cfg", serveConfig)
	mux.GET("/boot", serveBoot)
	mux.GET("/boot/:id", serveSavedBoot)

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
	buf.WriteString("#!/bin/sh\n")

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

func serveBoot(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "text/plain")

	query := req.URL.Query()

	const minBufferSize = 600
	buf := bytes.NewBuffer(make([]byte, 0, minBufferSize))
	buf.WriteString("#!ipxe\n")

	base, err := url.Parse(query.Get("base"))
	if err != nil {
		http.Error(w, "cannot parse baseurl: "+err.Error(), http.StatusBadRequest)
		return
	}

	base.Fragment = ""
	base.RawQuery = ""

	formatPath := func(s string) string {
		return s
	}
	if *base != (url.URL{}) {
		base.RawQuery = base.Query().Encode()
		base.Path = path.Clean(base.Path)
		if base.Path == "." {
			base.Path = "/"
		}

		formatPath = func(s string) string {
			return path.Join("${base-url}", s)
		}
		fmt.Fprintln(buf, `set base-url`, base)
	}

	configURL := generateConfigURL(req, query)
	if configURL != nil {
		fmt.Fprintln(buf, `set config-url`, configURL)
	}

	kernel := query.Get("kernel")
	if kernel == "" {
		kernel = "vmlinuz"
	}
	io.WriteString(buf, "kernel "+formatPath(kernel))

	if passDefaults, _ := strconv.ParseBool(query.Get("defaults")); passDefaults {
		// Default arguments
		io.WriteString(buf, ` root=/dev/null ip=dhcp vconsole.keymap=us locale.LANG=en_US.UTF-8`)
	}

	for _, arg := range query["append"] {
		io.WriteString(buf, " "+arg)
	}

	if configURL != nil {
		io.WriteString(buf, ` auto autourl=${config-url}`)
	}

	io.WriteString(buf, "\n")

	initrd := query.Get("initrd")
	if initrd == "" && query["initrd"] != nil {
		initrd = "initrd"
	}
	if initrd != "" {
		io.WriteString(buf, "initrd "+formatPath(initrd)+"\n")
	}

	fmt.Fprintln(buf, "boot")

	allowSave := isAuthed(req)
	if save, _ := strconv.ParseBool(query.Get("save")); allowSave && save {
		key := saveConfig(buf.Bytes())
		buf.Reset()
		buf.WriteString(key)
	}

	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	buf.WriteTo(w)
}

type savedConfig struct {
	ID     string
	From   time.Time
	Config string
}

func (s *savedConfig) String() string {
	if s == nil {
		return ""
	}
	return s.Config
}

func (s *savedConfig) Len() int {
	if s == nil {
		return 0
	}
	return len(s.Config)
}

// TODO: Replace with bolt, probably, so these can be persisted.
// TODO: Also allow removal of existing configs before long-term persistence is added.
var allSavedConfigs = map[string]*savedConfig{}
var savedConfigsLock sync.RWMutex

func purgeOldConfigs(keepMinNewest int) {
	current := getSavedConfigs()
	if len(current) < keepMinNewest {
		return
	}

	sort.Slice(current, func(i, j int) bool {
		return current[j].From.Before(current[j].From)
	})

	current = current[:len(current)-keepMinNewest]
	if len(current) == 0 {
		return
	}

	savedConfigsLock.Lock()
	defer savedConfigsLock.Unlock()
	for _, v := range current {
		delete(allSavedConfigs, v.ID)
	}
}

func getSavedConfigs() []*savedConfig {
	savedConfigsLock.RLock()
	defer savedConfigsLock.RUnlock()
	values := make([]*savedConfig, 0, len(allSavedConfigs))
	for _, v := range allSavedConfigs {
		values = append(values, v)
	}
	return values
}

func saveConfig(config []byte) (key string) {
	h := hmac.New(sha256.New, authHash)
	h.Write(config)
	sum := h.Sum(make([]byte, 0, h.Size()))
	key = zbase32.EncodeToString(sum)

	ref := &savedConfig{
		ID:     key,
		From:   time.Now(),
		Config: string(config),
	}

	savedConfigsLock.Lock()
	defer savedConfigsLock.Unlock()
	allSavedConfigs[key] = ref

	return key
}

func serveSavedBoot(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	key := params[0].Value

	savedConfigsLock.RLock()
	config := allSavedConfigs[key]
	savedConfigsLock.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(config.Len()))
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, config.String())
}

var configURLBase = url.URL{
	Scheme: "https",
	Host:   "void.spiff.io",
	Path:   "/autoinstall.cfg",
}

func isAuthed(req *http.Request) bool {
	password := req.Header.Get("Save-Token")
	return len(authHash) > 0 && password != "" &&
		bcrypt.CompareHashAndPassword(authHash, []byte(password)) == nil
}

func generateConfigURL(req *http.Request, query url.Values) *url.URL {
	configParams := url.Values{}
	for k, v := range query {
		if strings.HasPrefix(k, "cfg_") && k != "cfg_" {
			k = k[4:]
			configParams[k] = v
		}
	}

	user, password, haveAuth := req.BasicAuth()
	if len(configParams) == 0 && !haveAuth {
		return nil
	}

	configURL := configURLBase
	configURL.RawQuery = configParams.Encode()
	configURL.Fragment = ""
	if haveAuth {
		configURL.User = url.UserPassword(user, password)
	}

	// Add &/autoinstall.cfg to the end of the query string. This is needed to get around
	// xbps-uhelper's fetch command not removing query strings from URLs, so when it fetches
	// a file, it will include the query string in the basename. In particular, however, we do
	// not want the / in this parameter encoded.
	if configURL.RawQuery != "" {
		configURL.RawQuery += "&/autoinstall.cfg"
	}

	return &configURL
}
