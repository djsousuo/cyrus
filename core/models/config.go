package models

import (
	"github.com/jinzhu/configor"
)

type ConfigStruct struct {
	Module map[string]map[string]string

	Scan struct {
		Exclude []string
		Scope   []string
		Retry   int `default:"3"`
	}

	Browser struct {
		Addr string `default:"http://localhost:5050/"`
	}

	Redis struct {
		Addr         string `default:"localhost:6379"`
		Password     string `default:""`
		FlushOnStart bool   `default:"false"`
	}

	RabbitMQ struct {
		Addr         string `default:"amqp://guest:guest@localhost:5672/"`
		ExchangeName string `default:"records"`
	}

	Proxy struct {
		Addr string `default:"0.0.0.0:8080"`
	}
}

var Config ConfigStruct

func LoadConfig(path string) error {
	Config = ConfigStruct{}
	return configor.New(&configor.Config{ErrorOnUnmatchedKeys: true}).Load(&Config, path)
}
