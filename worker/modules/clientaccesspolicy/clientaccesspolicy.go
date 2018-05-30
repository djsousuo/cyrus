package main

import (
	"../../../core/cache"
	"../../../core/models"
	"log"
	"encoding/xml"
	"strings"
	"fmt"
)

type module bool

var info = models.ModuleInfo{
	ID:          "clientaccesspolicy-module",
	Name:        "ClientAccessPolicy",
	Description: "Checks ClientAccessPolicy.xml",
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

		err := cache.Set(key, 1)
		if err != nil {
			log.Print("Error catching result ", err)
		}

		test := rec
		test.Req.Method = "GET"
		test.Req.URL.RawQuery = ""
		test.Req.URL.Path = "/ClientAccessPolicy.xml"
		err = test.Send()
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
					if se.Name.Local == "domain" {
						for _, attr := range se.Attr {
							if attr.Name.Local == "uri" {
								if attr.Value == "*" || attr.Value == "http://*" || attr.Value == "https://*" {
									test.AddVulnerability(models.Vulnerability{
										Name:     "ClientAccessPolicy",
										Desc:     fmt.Sprintf("No access source limit set on: %v", test.Req.URL.String()),
										Severity: models.MEDIUM,
										Links:    []string{"http://www.silverlighthack.com/post/2008/11/08/Silverlight-clientaccesspolicyxml-files-for-the-Enterprise-(Part-1-of-2).aspx"},
									})
									out <- test
								} else {
									test.AddVulnerability(models.Vulnerability{
										Name:     "ClientAccessPolicy",
										Desc:     fmt.Sprintf("%v is allowed to access(%v)", attr.Value, test.Req.URL.String()),
										Severity: models.LOW,
										Links:    []string{"http://www.silverlighthack.com/post/2008/11/08/Silverlight-clientaccesspolicyxml-files-for-the-Enterprise-(Part-1-of-2).aspx"},
									})
									out <- test
								}
							}
						}
					}
				}
			}

		}
	}
	return nil
}

var Module module
