package main

import (
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"path"
	"regexp"
	"strings"
)

type Validator interface {
	Check(string) error
}

type passValidator int

const Pass passValidator = 0

func (passValidator) Check(string) error {
	return nil
}

type Validators []Validator

func (v Validators) Check(s string) error {
	for _, inner := range v {
		if err := inner.Check(s); err != nil {
			return err
		}
	}
	return nil
}

type positiveInteger int

const PositiveInteger positiveInteger = 0

var bigZero = &big.Int{}

func (positiveInteger) Check(s string) error {
	var i big.Int
	if _, ok := i.SetString(s, 10); !ok {
		return fmt.Errorf("%q is not a valid base-10 integer", s)
	} else if i.Cmp(bigZero) <= 0 {
		return fmt.Errorf("must be >= 0, got %v", i)
	}
	return nil
}

type Choice []string

func (c Choice) Check(s string) error {
	for _, choice := range c {
		if s == choice {
			return nil
		}
	}
	return fmt.Errorf("must match one of %q", []string(c))
}

type RegexpValidator struct {
	regex *regexp.Regexp
}

func MustValidateRegexp(spec string) *RegexpValidator {
	rx := regexp.MustCompile(spec)
	return &RegexpValidator{
		regex: rx,
	}
}

func (r *RegexpValidator) Check(s string) error {
	if !r.regex.MatchString(s) {
		return fmt.Errorf("must match regexp /%v/", r.regex)
	}
	return nil
}

type MinLength int

const Nonempty MinLength = 1

func (m MinLength) Check(s string) error {
	if m == 1 && s == "" {
		return errors.New("must not be empty")
	} else if len(s) < int(m) {
		return fmt.Errorf("must be at least %d characters", int(m))
	}
	return nil
}

type MaxLength int

func (m MaxLength) Check(s string) error {
	if len(s) > int(m) {
		return fmt.Errorf("must be %d characters or less", int(m))
	}
	return nil
}

type nonemptyTrimmed int

const NonemptyTrimmed nonemptyTrimmed = 0

func (nonemptyTrimmed) Check(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("must not be empty (not counting whitespace)")
	}
	return nil
}

type httpOrFileURL int

const HTTPOrFileURL httpOrFileURL = 0

func (httpOrFileURL) Check(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "file":
		empty := url.URL{Scheme: u.Scheme, Path: u.Path}
		if empty != *u {
			return errors.New("file URLs may only contain a path")
		}
		if !path.IsAbs(u.Path) {
			return errors.New("file URLs must be absolute")
		}
		return nil

	case "http", "https":
		return nil

	default:
		return errors.New("bad URL scheme; must be http://, https://, or file://")
	}
}

type pathOrHTTP int

const PathOrHTTP pathOrHTTP = 0

func (pathOrHTTP) Check(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "":
		empty := url.URL{Path: u.Path}
		if empty != *u {
			return errors.New("invalid file path")
		}
		if !path.IsAbs(u.Path) {
			return errors.New("file paths must be absolute")
		}
		return nil

	case "http", "https":
		return nil

	default:
		return errors.New("bad URL scheme; must be http://, https://, or absolute path")
	}
}

type absPath int

const IsAbsPath absPath = 0

func (absPath) Check(s string) error {
	if !path.IsAbs(s) {
		return errors.New("file path must be absolute")
	}
	return nil
}
