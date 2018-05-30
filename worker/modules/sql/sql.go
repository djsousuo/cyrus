package main

import (
	"../../../core/models"
	"../../../core/utils"
	"github.com/jinzhu/configor"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
	"bytes"
)

type sqlConfig struct {
	Parameter []string
	parameter []*regexp.Regexp

	Error []struct {
		Name  string
		Basic []string
		Regex []string
		regex []*regexp.Regexp
	}

	Time struct {
		Sleep   int
		Payload []string
		payload []string
	}
}

var config sqlConfig

func submit(rec models.Record, desc string, out chan<- models.Record) {
	rec.AddVulnerability(models.Vulnerability{
		Name:     "SQL Injection",
		Desc:     desc,
		Severity: models.HIGH,
		Links:    []string{"https://www.owasp.org/index.php/SQL_Injection"},
	})
	out <- rec
}

type module bool

var info models.ModuleInfo

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {
	err := configor.New(&configor.Config{ErrorOnUnmatchedKeys: true}).Load(&config, dir+"/sql.yml")
	if err != nil {
		return info, err
	}

	//Precompile regex
	for _, reg := range config.Parameter {
		config.parameter = append(config.parameter, regexp.MustCompile(reg))
	}

	//Precompile regex
	for _, d := range config.Error {
		for _, reg := range d.Regex {
			d.regex = append(d.regex, regexp.MustCompile(reg))
		}
	}

	//replace time
	for _, d := range config.Time.Payload {
		config.Time.payload = append(config.Time.payload, strings.Replace(d, "__TIME__", strconv.Itoa(config.Time.Sleep), -1))
	}

	info = models.ModuleInfo{
		ID:   "sql-module",
		Name: "SQL Module",
	}
	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) (err error) {
outter:
	for rec := range inp {
		//check pattern
		check := string(rec.Req.Content)
		for k, vs := range rec.Req.URL.Query() {
			for _, v := range vs {
				check += "&" + k + "=" + v
			}
		}
		check = strings.ToUpper(check)

		for _, p := range config.parameter {
			if p.MatchString(check) {
				submit(rec, "SQL Statement", out)
				break
			}
		}

		// Error Based
		for _, inj := range utils.Inject(rec.Req, []string{"\xBF'\"(", "'\"("}) {
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
				for _, reg := range d.regex {
					if reg.Match(resp.Content) {
						submit(test, "Error based", out)
						continue outter
					}
				}
			}
		}
		// Time Based
		for _, inj := range utils.Inject(rec.Req, config.Time.payload) {
			sqli := true
			var resp models.Response
			for i := 0; i < models.Config.Scan.Retry; i++ {
				resp, err := inj.Send()
				if err != nil {
					log.Print("Sending request failed: ", err)
					continue outter
				}

				if resp.Took < time.Duration(config.Time.Sleep)*time.Second {
					sqli = false
					break
				}
			}

			if sqli {
				test := models.NewRecord(inj, resp)

				submit(test, "Time based", out)
				continue outter
			}

		}

	}
	return nil
}

var Module module
