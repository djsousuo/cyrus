package main

import (
	"bytes"
	"github.com/google/uuid"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"log"
)

type module bool

var info = models.ModuleInfo{
	ID:          "xst-module",
	Name:        "xst",
	Description: "Cross-Site Tracing (XST)",
}

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {
	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
	for rec := range inp {
		u := rec.Req.URL
		u.Fragment = ""
		u.RawQuery = ""
		baseURL := u.String()
		key := info.ID + baseURL
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}

		test := rec
		test.Req.Method = "TRACE"
		test.Req.Content = []byte(uuid.New().String())
		err := test.Send()
		if err != nil {
			log.Print(err)
			continue
		}

		if bytes.Contains(test.Resp.Content, test.Req.Content) {
			test.AddVulnerability(models.Vulnerability{
				Name:     "XST",
				Desc:     "Cross-Site Tracing (XST)",
				Severity: models.MEDIUM,
				Links:    []string{"https://www.owasp.org/index.php/Cross_Site_Tracing"},
			})
			out <- test
		}

		err = cache.Set(key, 1)
		if err != nil {
			log.Print("Error catching result ", err)
		}
	}
	return nil
}

var Module module
