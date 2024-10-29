// database.go

package database

import (
	"errors"
	"fmt"
	"sync"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Database struct {
	DB   *gorm.DB
	once sync.Once
}

func NewDatabase() *Database {
	return &Database{}
}

// Connect method now returns the database instance.
func (db *Database) Connect() (*gorm.DB, error) { // Change return type
	var err error

	db.once.Do(func() {
		cfg, err := config.LoadConfig()
		if err != nil {
			logrus.Fatalf("Failed to load config: %v", err)
		}

		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			cfg.Database.DBUser, cfg.Database.DBPassword, cfg.Database.DBHost, cfg.Database.DBPort, cfg.Database.DBName)

		logrus.Infof("Connecting to database with DSN: %s", dsn)

		connection, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			logrus.Errorf("Failed to connect to database: %v", err)

			return
		}

		db.DB = connection

		if err := db.DB.AutoMigrate(&models.User{}); err != nil { // Handle migration
			logrus.Errorf("Error during AutoMigrate: %v", err)
		}
	})

	if db.DB == nil {
		return nil, errors.New("failed to initialize database connection")
	}

	return db.DB, err // Return the DB instance and error
}

// GetDB now returns the database instance.
func GetDB() *gorm.DB {
	db := NewDatabase()
	conn, err := db.Connect() // Get DB instance from Connect

	if err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}

	return conn // Return the database connection
}
