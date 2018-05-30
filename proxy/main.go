package main

import (
	"../core/cache"
	"../core/models"
	"../core/mq"
	"../core/proxy"
	"../core/utils"
	"bytes"
	"encoding/gob"
	"flag"
)

func main() {

	configFile := flag.String("config", "config.yml", "Path of configuration file")
	flag.Parse()

	err := models.LoadConfig(*configFile)
	utils.FailOnError(err, "Reading config file failed")

	err = cache.Connect(models.Config.Redis.Addr, models.Config.Redis.Password)
	utils.FailOnError(err, "Connecting to redis failed")

	b := new(bytes.Buffer)
	err = gob.NewEncoder(b).Encode(models.Config)
	utils.FailOnError(err, "Encoding config failed")

	err = cache.Set("Config", b.Bytes())
	utils.FailOnError(err, "Sending configuration to Cache server failed")

	err = mq.Connect(true)
	utils.FailOnError(err, "Connecting to AMQP failed")

	proxy.StartProxy(models.Config.Proxy.Addr)
}
