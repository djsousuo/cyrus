package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var emailRegexp = regexp.MustCompile("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")

func extractEmails(body string) (ret []string) {
	for _, email := range emailRegexp.FindAllString(body, -1) {
		if validateEmailHost(email) {
			ret = append(ret, email)
		}
	}
	return ret
}

func validateEmailHost(email string) bool {
	p := strings.Split(email, "@")

	if len(p) < 2 {
		return false
	}
	host := p[1]

	_, err := net.LookupMX(host)
	return err == nil
}

func checkLeak(email string) ([]string, error) {
	u := fmt.Sprintf("https://hacked-emails.com/api?q=%s", url.QueryEscape(email))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var leaks struct {
		Status string
		Data   []struct {
			Title string
		} `json:"data,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&leaks); err != nil {
		return nil, err
	}
	if leaks.Status == "apilimit" {
		return nil, errors.New("reached ratelimit")
	}
	var titles []string
	for _, d := range leaks.Data {
		titles = append(titles, d.Title)
	}
	return titles, nil
}

type module bool

var info = models.ModuleInfo{
	ID:   "email-module",
	Name: "Email Module",
}

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {

	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
	for rec := range inp {
		emails := extractEmails(string(rec.Resp.Content))
		if len(emails) > 0 {
			test := rec
			test.AddVulnerability(models.Vulnerability{
				Name:     "Email",
				Desc:     fmt.Sprintf("found %v", strings.Join(emails, ", ")),
				Severity: models.LOW,
			})
			for _, email := range emails {
				key := info.ID + email
				if _, err := cache.Get(key); err == nil {
					//Already checked
					continue
				}

				leaks, err := checkLeak(email)
				if err != nil {
					log.Print("Getting leaks failed: ", err)
					continue
				}

				if len(leaks) > 0 {
					test.AddVulnerability(models.Vulnerability{
						Name:     "Email with leaked password",
						Desc:     fmt.Sprintf("%q found in leak databases: %v ", email, strings.Join(leaks, ", ")),
						Severity: models.HIGH,
					})
				}

				err = cache.Set(key, 1)
				if err != nil {
					log.Print("Error catching result ", err)
				}
			}
			out <- test
		}

	}
	return nil
}

var Module module
