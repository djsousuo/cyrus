package main

import (
	"encoding/xml"
	"fmt"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"log"
	"strings"
)

type module bool

var info = models.ModuleInfo{
	ID:          "crossdomain-module",
	Name:        "Crossdomain",
	Description: "Checks crossdomain.xml",
}

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {
	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
	for rec := range inp {
		key := info.ID + rec.Req.URL.Host
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}

		test := rec
		test.Req.Method = "GET"
		test.Req.URL.RawQuery = ""
		test.Req.URL.Path = "/crossdomain.xml"
		err := test.Send()
		if err != nil {
			log.Print(err)
			continue
		}

		if test.Resp.Status == 200 {
			decoder := xml.NewDecoder(strings.NewReader(string(test.Resp.Content)))

			for {
				// Read tokens from the XML document in a stream.
				t, _ := decoder.Token()
				if t == nil {
					break
				}
				// Inspect the type of the token just read.
				switch se := t.(type) {
				case xml.StartElement:
					if se.Name.Local == "allow-access-from" {
						for _, attr := range se.Attr {
							if attr.Name.Local == "domain" {
								if attr.Value == "*" {
									test.AddVulnerability(models.Vulnerability{
										Name:     "crossdomain",
										Desc:     fmt.Sprintf("No access source limit set on: %v", test.Req.URL.String()),
										Severity: models.MEDIUM,
										Links:    []string{"https://thehackerblog.com/building-an-rdio-flash-cross-domain-exploit-with-flashhttprequest-crossdomain-xml-security/index.html"},
									})
									out <- test
								} else {
									test.AddVulnerability(models.Vulnerability{
										Name:     "crossdomain",
										Desc:     fmt.Sprintf("%v is allowed to access(%v)", attr.Value, test.Req.URL.String()),
										Severity: models.LOW,
										Links:    []string{"https://thehackerblog.com/building-an-rdio-flash-cross-domain-exploit-with-flashhttprequest-crossdomain-xml-security/index.html"},
									})
									out <- test
								}
							}
						}
					}
				}
			}
		}

		err = cache.Set(key, 1)
		if err != nil {
			log.Print("Error catching result ", err)
		}
	}
	return nil
}

var Module module
