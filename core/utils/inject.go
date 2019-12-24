package utils

import (
	"encoding/json"
	"github.com/nim4/cyrus/core/models"
	"net/http"
	"net/url"
	"strings"
)

const separator = "/"

func payloadQueryString(req models.Request, key, payload string, add bool) models.Request {
	u := *req.URL
	injectedQ := u.Query()
	if add {
		injectedQ.Add(key, payload)
	} else {
		injectedQ.Set(key, payload)
	}
	u.RawQuery = injectedQ.Encode()
	injected := req
	injected.URL = &(u)
	return injected
}

func payloadQueryBody(req models.Request, key, payload string, add bool) (injected models.Request, err error) {
	values, err := url.ParseQuery(string(req.Content))
	if err != nil {
		return
	}
	if add {
		values.Add(key, payload)
	} else {
		values.Set(key, payload)
	}
	injected = req
	injected.Content = []byte(values.Encode())
	return
}

func payloadHeader(req models.Request, key, payload string, add bool) models.Request {
	head := http.Header{}
	for key, value := range req.Headers {
		for _, v := range value {
			head.Set(key, v)
		}
	}

	if add {
		head.Add(key, payload)
	} else {
		head.Set(key, payload)
	}

	injected := req
	injected.Headers = head
	return injected
}

func pathInject(req models.Request, payload string) []models.Request {
	var ret []models.Request

	dirs := strings.Split(req.URL.Path, separator)
	if len(dirs) == 1 {
		return nil
	}

	dirs = dirs[1:]
	for i := range dirs {
		var path = make([]string, len(dirs))
		copy(path, dirs[:i])
		path[i] = payload
		copy(path[i+1:], dirs[i+1:])
		injected := req
		u := *req.URL
		injected.URL = &(u)
		injected.URL.Path = separator + strings.Join(path, separator)
		ret = append(ret, injected)
	}
	return ret
}

func queryStringInject(req models.Request, payload string) []models.Request {
	var ret []models.Request

	for k, vs := range req.URL.Query() {
		ret = append(ret, payloadQueryString(req, k, payload, false))
		ret = append(ret, payloadQueryString(req, k, payload, true))
		for _, v := range vs {
			ret = append(ret, payloadQueryString(req, k, v+payload, false))
		}
	}

	ret = append(ret, payloadQueryString(req, payload, "1", false))
	return ret
}

func headerInject(req models.Request, payload string) []models.Request {
	var ret []models.Request

	for k, vs := range req.Headers {
		ret = append(ret, payloadHeader(req, k, payload, false))
		ret = append(ret, payloadHeader(req, k, payload, true))
		for _, v := range vs {
			ret = append(ret, payloadHeader(req, k, v+payload, false))
		}
	}

	ret = append(ret, payloadHeader(req, payload, "1", false))
	return ret
}

func bodyInject(req models.Request, payload string) []models.Request {
	var ret []models.Request

	switch req.Headers.Get("Content-Type") {
	case "application/json":
		var j map[string]interface{}
		var err error
		json.Unmarshal(req.Content, &j)
		for k, v := range j {
			j[k] = payload
			injected := req
			injected.Content, err = json.Marshal(j)
			if err == nil {
				ret = append(ret, injected)
			}
			j[k] = v
		}
		j[payload] = "1"
		injected := req
		injected.Content, err = json.Marshal(j)
		if err == nil {
			ret = append(ret, injected)
		}
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(req.Content))
		if err == nil {
			for k, vs := range values {
				r, err := payloadQueryBody(req, k, payload, false)
				if err == nil {
					ret = append(ret, r)
				}
				r, err = payloadQueryBody(req, k, payload, true)
				if err == nil {
					ret = append(ret, r)
				}

				for _, v := range vs {
					r, err := payloadQueryBody(req, k, v+payload, false)
					if err == nil {
						ret = append(ret, r)
					}
				}
			}

			r, err := payloadQueryBody(req, payload, "1", true)
			if err == nil {
				ret = append(ret, r)
			}

		}
	}

	return ret
}

func Inject(req models.Request, payloads []string) (ret []models.Request) {
	for _, payload := range payloads {
		for _, f := range []func(models.Request, string) []models.Request{
			queryStringInject,
			//bodyInject,
			//pathInject,
			//headerInject,
		} {
			i := f(req, payload)
			if i != nil {
				ret = append(ret, i...)
			}
		}
	}
	return
}
