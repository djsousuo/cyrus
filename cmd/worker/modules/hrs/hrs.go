package main

import (
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"github.com/nim4/cyrus/core/utils"
	"log"
)

func submit(rec models.Record, desc string, out chan<- models.Record) {
	rec.AddVulnerability(models.Vulnerability{
		Name:     "HTTP Response Splitting (HRS)",
		Desc:     desc,
		Severity: models.MEDIUM,
		Links:    []string{"https://www.owasp.org/index.php/HTTP_Response_Splitting"},
	})
	out <- rec
}

type module bool

func (m module) OnLoad(dir string) (info models.ModuleInfo, err error) {
	info = models.ModuleInfo{
		ID:   "hrs",
		Name: "HRS Module",
	}

	return
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
outter:
	for rec := range inp {

		key := rec.ID.String()
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}

		for _, inj := range utils.Inject(rec.Req, []string{"\r\nCyr: 1"}) {
			resp, err := inj.Send()
			if err != nil {
				log.Print("Sending request failed: ", err)
				continue
			}

			test := models.NewRecord(inj, resp)

			if resp.Headers.Get("Cyr") != "" {
				submit(test, "Injected header found", out)
				continue outter
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
