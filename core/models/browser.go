package models

import (
	"net/http"
	"bytes"
	"time"
	"io/ioutil"
	"errors"
	"encoding/json"
)

type BrowserRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type BrowserResponse struct {
	Status int
	Body   []byte
	Took   time.Duration
}

func FromRequest(req Request) (br BrowserRequest) {
	br = BrowserRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Body:    string(req.Content),
	}


	br.Headers = make(map[string]string)
	for k, v := range req.Headers {
		br.Headers[k] = v[0]
	}

	return
}


func (br *BrowserRequest) Send(endpoint string) (resp BrowserResponse, err error) {
	for i := 0; i < Config.Scan.Retry; i++ {
		client := &http.Client{}

		var b []byte
		b, err = json.Marshal(br)
		if err != nil {
			return
		}

		var req *http.Request
		var result *http.Response

		req, err = http.NewRequest("POST", Config.Browser.Addr+endpoint, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		result, err = client.Do(req)
		if err != nil {
			continue
		}

		took := time.Since(start)
		b, err = ioutil.ReadAll(result.Body)
		if err != nil {
			return
		}

		resp = BrowserResponse{
			Status: result.StatusCode,
			Body:   b,
			Took:   took,
		}
		return
	}
	err = errors.New("max retry reached")
	return
}
