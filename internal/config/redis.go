package config

import (
	"context"
	"log"

	"github.com/go-redis/redis/v8"
)

func InitRedis(cfg *Config) *redis.Client {
	ctx := context.Background() // Local context variable

	opt, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		log.Fatal("Failed to parse Redis URL:", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	_, err = client.Ping(ctx).Result()
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connected successfully")
	return client
}
