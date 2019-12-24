package models

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//Request holder model
type Request struct {
	Method  string
	URL     *url.URL
	Proto   string
	Headers http.Header
	Content []byte
}

//LogString of the Request
func (r *Request) LogString() string {
	if r == nil {
		return "Request{}"
	}
	return fmt.Sprintf(
		"Request{Method: %q, URL: %q, Headers: %v, ContentLength: %v}",
		r.Method,
		r.URL.String(),
		r.Headers,
		len(r.Content),
	)
}

//Send request and fill response
func (r *Request) Send() (Response, error) {
	for i := 0; i < Config.Scan.Retry; i++ {
		client := &http.Client{}

		req, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(r.Content))
		if err != nil {
			return Response{}, err
		}

		req.Header = r.Headers

		if req.Header.Get("Content-Length") != "" {
			req.Header.Set("Content-Length", strconv.Itoa(len(r.Content)))
		}

		start := time.Now()
		result, err := client.Do(req)
		if err != nil {
			continue
		}

		took := time.Since(start)
		b, err := ioutil.ReadAll(result.Body)
		if err != nil {
			return Response{}, err
		}
		return Response{
			Status:  result.StatusCode,
			Proto:   result.Proto,
			Headers: result.Header,
			Content: b,
			Took:    took,
		}, nil
	}
	return Response{}, errors.New("max retry reached")
}

//Response model
type Response struct {
	Status  int
	Proto   string
	Headers http.Header
	Content []byte
	Took    time.Duration
}

//LogString of the Response
func (r *Response) LogString() string {
	if r == nil {
		return "Response{}"
	}
	return fmt.Sprintf(
		"Response{Method: %v, Proto: %q, Headers: %v, ContentLength: %v, Took: %q}",
		r.Status,
		r.Proto,
		r.Headers,
		len(r.Content),
		r.Took,
	)
}

const (
	LOW = iota
	MEDIUM
	HIGH
)

type severity int

//Vulnerability of Record
type Vulnerability struct {
	Name     string
	Desc     string
	Severity severity
	Links    []string
}

//LogString of the Vulnerability
func (v *Vulnerability) LogString() string {
	if v == nil {
		return "Vulnerability{}"
	}
	return fmt.Sprintf(
		"Vulnerability{Name: %q, Desc: %q, Links: %q}",
		v.Name,
		v.Desc,
		v.Links,
	)
}

//Record of the tasks
type Record struct {
	ID              uuid.UUID
	Req             Request
	Resp            Response
	Vulnerabilities []Vulnerability
}

//Send request and fill response
func (r *Record) Send() error {
	var err error
	r.Resp, err = r.Req.Send()
	return err
}

func (r *Record) AddVulnerability(v Vulnerability) {
	r.Vulnerabilities = append(r.Vulnerabilities, v)
}

//LogString of the record
func (r *Record) LogString() string {
	if r == nil {
		return "Record{}"
	}

	var vuln []string
	for _, v := range r.Vulnerabilities {
		vuln = append(vuln, v.LogString())
	}

	return fmt.Sprintf(
		"Record{ID: %q, %v, %v, %v}",
		r.ID,
		r.Req.LogString(),
		r.Resp.LogString(),
		"["+strings.Join(vuln, ", ")+"]",
	)
}

func NewRecord(req Request, resp Response) Record {
	return Record{
		ID:   uuid.New(),
		Req:  req,
		Resp: resp,
	}
}
