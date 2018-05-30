package main

import (
	"../../../core/models"
	"../../../core/utils"
	"github.com/jinzhu/configor"
	"log"
	"bytes"
)

type xpathConfig struct {
	Error []struct {
		Basic []string
	}
}

var config xpathConfig

func submit(rec models.Record, desc string, out chan<- models.Record) {
	rec.AddVulnerability(models.Vulnerability{
		Name:     "XPATH Injection",
		Desc:     desc,
		Severity: models.HIGH,
		Links:    []string{"https://www.owasp.org/index.php/XPATH_Injection"},
	})
	out <- rec
}

type module bool

var info models.ModuleInfo

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {
	err := configor.New(&configor.Config{ErrorOnUnmatchedKeys: true}).Load(&config, dir+"/xpath.yml")
	if err != nil {
		return info, err
	}

	info = models.ModuleInfo{
		ID:   "xpath-module",
		Name: "XPATH Module",
	}
	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) (err error) {
outter:
	for rec := range inp {
		// Error Based
		for _, inj := range utils.Inject(rec.Req, []string{"'\"", "]]]]]]]]]", "<!--"}) {
			resp, err := inj.Send()
			if err != nil {
				log.Print("Sending request failed: ", err)
				continue
			}

			test := models.NewRecord(inj, resp)

			for _, d := range config.Error {
				for _, basic := range d.Basic {
					if bytes.Contains(resp.Content, []byte(basic)) {
						submit(test, "Error based", out)
						continue outter
					}
				}
			}
		}
	}
	return nil
}

var Module module
