package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func AccessLog(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		rc := responseCodeCapture{ResponseWriter: w}
		t := time.Now()

		addr := req.RemoteAddr
		u := *req.URL

		next.ServeHTTP(&rc, req)

		// Do not log 404s or 0s
		switch rc.Code {
		case 0, http.StatusNotFound, http.StatusNotModified:
			return
		}

		elapsed := time.Since(t).Seconds()
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			addr += "," + xff
		}

		query := u.Query()
		for k, _ := range query {
			switch strings.ToLower(k) {
			case "user", "username", "pass", "password":
				// Omit these from logs -- user and pass aren't even used, but omit
				// them anyway in case someone made a typo while testing something.
				delete(query, k)
			}
		}
		u.RawQuery = query.Encode()

		requri := strconv.QuoteToASCII(u.RequestURI())
		requri = requri[1 : len(requri)-1]
		log.Printf("%d %s %d %f %s %s",
			rc.Code,
			req.Method,
			rc.Bytes,
			elapsed,
			requri,
			addr,
		)
	}
}

type responseCodeCapture struct {
	Bytes int64
	Code  int
	set   bool
	http.ResponseWriter
}

func (r *responseCodeCapture) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code)
	if r.set {
		return
	}
	r.set, r.Code = true, code
}

func (r *responseCodeCapture) Write(b []byte) (int, error) {
	if !r.set {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.Bytes += int64(n)
	return n, err
}

func (r *responseCodeCapture) WriteString(s string) (int, error) {
	type stringWriter interface {
		WriteString(string) (int, error)
	}
	if sw, ok := r.ResponseWriter.(stringWriter); ok {
		n, err := sw.WriteString(s)
		r.Bytes += int64(n)
		return n, err
	}
	return r.Write([]byte(s))
}
