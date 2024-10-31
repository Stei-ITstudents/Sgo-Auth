package models

import "time"

type User struct {
	ID                uint      `gorm:"primaryKey"      json:"id"`
	Name              string    `gorm:"size:255"        json:"name"`
	Email             string    `gorm:"size:255;unique" json:"email"`
	Password          []byte    `gorm:"size:255"        json:"-"`
	Role              string    `gorm:"size:50"         json:"role"`
	UserID            string    `gorm:"size:255"        json:"userId"`
	AuthMethod        string    `gorm:"size:50"         json:"authMethod"`
	AccessToken       []byte    `gorm:"size:255"        json:"accessToken"`
	RefreshToken      []byte    `gorm:"size:255"        json:"-"`
	ClientID          string    `gorm:"size:255"        json:"clientId"`
	IPAddress         string    `gorm:"size:45"         json:"-"`
	UserAgent         string    `gorm:"size:255"        json:"-"`
	CreatedAt         time.Time `gorm:"autoCreateTime"  json:"-"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime"  json:"-"`
	LastLoginAt       time.Time `gorm:"autoUpdateTime"  json:"-"`
	IsActive          bool      `gorm:"default:true"    json:"isActive"`
	ProfilePictureURL string    `gorm:"size:255"        json:"profilePictureUrl"`
	PhoneNumber       string    `gorm:"size:20"         json:"-"`
	Address           string    `gorm:"size:255"        json:"address"`
	TwoFactorEnabled  bool      `gorm:"default:false"   json:"twoFactorEnabled"`
}
