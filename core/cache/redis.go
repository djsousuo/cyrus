package cache

import (
	"github.com/go-redis/redis"

	"../models"
)

var client *redis.Client

func Connect(addr, password string) error {
	client = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})

	err := client.Ping().Err()
	if err != nil {
		return err
	}

	if models.Config.Redis.FlushOnStart {
		return flush()
	}

	return nil
}

func Set(key string, value interface{}) error {
	return client.Set(key, value, 0).Err()
}

func Get(key string) (string, error) {
	return client.Get(key).Result()
}

func GetBytes(key string) ([]byte, error) {
	return client.Get(key).Bytes()
}

func flush() error {
	return client.FlushDB().Err()
}
