package main

import (
	"log"
	"path"
	"path/filepath"
	"plugin"

	"bytes"
	"encoding/gob"
	"flag"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"github.com/nim4/cyrus/core/mq"
	"github.com/nim4/cyrus/core/utils"
	"os"
	"strconv"
)

//Tasks holds loaded worker
var Tasks map[string]models.ModuleInfo

func main() {
	addr := flag.String("-a", "localhost:6379", "Address of the configuration server")
	password := flag.String("-p", "", "Password of the configuration server")

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lshortfile)

	cache.Connect(*addr, *password)
	b, err := cache.GetBytes("Config")
	utils.FailOnError(err, "Getting config from Cache server failed")

	r := bytes.NewReader(b)
	err = gob.NewDecoder(r).Decode(&models.Config)
	utils.FailOnError(err, "Decoding Cache server Config key failed")

	mq.Connect(false)
	utils.FailOnError(err, "Connecting to AMQP failed")

	out := loadModules()
	for rec := range out {
		log.Print(rec.LogString())
	}
}

func loadModules() <-chan models.Record {
	out := make(chan models.Record, 256)
	log.Print("Finding modules...")

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	modules, err := filepath.Glob(dir + "/addons/*.so")
	if err != nil {
		log.Fatal(err)
	}

	Tasks = make(map[string]models.ModuleInfo)
	for _, modPath := range modules {
		mod := path.Base(modPath)
		excluded := false
		for _, excludedMod := range models.Config.Scan.Exclude {
			if excludedMod == mod {
				excluded = true
				break
			}
		}

		if excluded {
			log.Printf("Skipped %v", mod)
			continue
		}

		log.Printf("Loading %v", mod)
		plug, err := plugin.Open(modPath)
		if err != nil {
			log.Fatal(err)
		}

		symTask, err := plug.Lookup("Module")
		if err != nil {
			log.Fatal(err)
		}

		task, ok := symTask.(models.Module)
		if !ok {
			log.Fatal("unexpected type from module symbol")
		}

		info, err := task.OnLoad(path.Dir(modPath))
		if err != nil {
			log.Printf("%v: Failed! Error: %v", mod, err)
		} else {
			info.Module = task
			Tasks[info.ID] = info
			inpChan, err := mq.Subscribe(info.ID)
			if err != nil {
				log.Fatal("subscribe failed: ", err)
			}

			workerCount := 1
			if m, ok := models.Config.Module[info.ID]; ok {
				if val, ok := m["worker"]; ok {
					workerCount, err = strconv.Atoi(val)
					if err != nil {
						log.Fatal("Invalid 'worker' config: ", err)
					}
				}
			}

			for w := 1; w <= workerCount; w++ {
				go task.Execute(inpChan, out)
			}

			log.Printf("%v OK", info.ID)
		}
	}
	log.Printf("Loaded %v modules", len(Tasks))
	return out
}
