package main

import (
	"../../../core/cache"
	"../../../core/models"
	"fmt"
	"log"
	"strings"
	"net/url"
	"os"
	"bufio"
	"net/http"
)

type module bool

var info = models.ModuleInfo{
	ID:   "dirbrute-module",
	Name: "Directory Brute-force Module",
}

var dictionary string

func baseUrl(u *url.URL) *url.URL {
	if !strings.HasSuffix(u.Path, "/") {
		parent, _ := url.Parse(".")
		u = u.ResolveReference(parent)
	}

	u.RawQuery = ""
	return u
}

func burte(base *url.URL) (ret []string, err error) {
	file, err := os.Open(dictionary)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		path := base.String() + scanner.Text()
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			ret = append(ret, path)
		}
	}

	err = scanner.Err()
	return
}

func (m module) OnLoad(dir string) (models.ModuleInfo, error) {
	// big.txt from SecLists
	dictionary = dir + "/dir.txt"
	return info, nil
}

func (m module) Execute(inp <-chan models.Record, out chan<- models.Record) error {
	for rec := range inp {
		u := baseUrl(rec.Req.URL)
		key := info.ID + u.String()
		if _, err := cache.Get(key); err == nil {
			//Already checked
			continue
		}
		err := cache.Set(key, 1)
		if err != nil {
			log.Print("Error catching key ", err)
		}

		founds, err := burte(u)
		if err != nil {
			log.Print(err)
			continue
		}

		if len(founds) > 0 {
			rec.AddVulnerability(models.Vulnerability{
				Name:     "Directory found",
				Desc:     fmt.Sprintf("Directories found: %v ", strings.Join(founds, ", ")),
				Severity: models.LOW,
			})
		}
		out <- rec
	}
	return nil
}

var Module module
