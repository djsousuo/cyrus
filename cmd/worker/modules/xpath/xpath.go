package main

import (
	"bytes"
	"github.com/jinzhu/configor"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"github.com/nim4/cyrus/core/utils"
	"log"
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
		key := rec.ID.String()
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}

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

		err := cache.Set(key, 1)
		if err != nil {
			log.Print("Error catching result ", err)
		}
	}
	return nil
}

var Module module
