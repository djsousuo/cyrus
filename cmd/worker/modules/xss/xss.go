package main

import (
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"github.com/nim4/cyrus/core/utils"
	"io/ioutil"
	"log"
	"strings"
)

var payload []string

func submit(rec models.Record, desc string, out chan<- models.Record) {
	rec.AddVulnerability(models.Vulnerability{
		Name:     "Cross-site Scripting (XSS)",
		Desc:     desc,
		Severity: models.MEDIUM,
		Links:    []string{"https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)"},
	})
	out <- rec
}

type module bool

func (m module) OnLoad(dir string) (info models.ModuleInfo, err error) {

	info = models.ModuleInfo{
		ID:   "xss",
		Name: "XSS Module",
	}

	// From SecLists
	b, err := ioutil.ReadFile(dir + "/xss.txt")
	if err != nil {
		return
	}

	trigger := "cyrizm()"
	if conf, ok := models.Config.Module[info.ID]; ok {
		if _, ok = conf["trigger"]; ok {
			trigger = conf["trigger"]
		}
	}

	for _, p := range strings.Split(string(b), "\n") {
		if len(p) > 0 {
			payload = append(payload, strings.Replace(p, "__FUNC__", trigger, -1))
		}
	}

	return
}

func checkXSS(rec models.Record) bool {

	br := models.FromRequest(rec.Req)

	resp, err := br.Send("xss")
	if err != nil {
		log.Print(err)
		return false
	}

	return string(resp.Body) == "1"
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
	for rec := range inp {
		key := rec.ID.String()
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}

		// Some checks to minimize selenium calls
		if rec.Resp.Headers.Get("Content-Type") != "" && !strings.Contains(rec.Resp.Headers.Get("Content-Type"), "text/html") {
			continue
		}

		for _, inj := range utils.Inject(rec.Req, payload) {
			resp, err := inj.Send()
			if err != nil {
				log.Print("Sending request failed: ", err)
				continue
			}

			test := models.NewRecord(inj, resp)

			if checkXSS(test) {
				submit(test, "XSS", out)
				break
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
