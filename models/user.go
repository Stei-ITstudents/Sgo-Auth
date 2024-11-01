package models

import "time"

type User struct {
	Provider            string    `gorm:"size:50"         json:"provider"`
	GoogleUserID        string    `gorm:"size:255"        json:"googleUserId"`
	FacebookUserID      string    `gorm:"size:255"        json:"facebookUserId"`
	GitHubUserID        string    `gorm:"size:255"        json:"githubUserId"`
	EmailUserID         string    `gorm:"size:255"        json:"emailUserId"`
	GoogleAccessToken   string    `gorm:"size:255"        json:"googleAccessToken"`
	FacebookAccessToken string    `gorm:"size:255"        json:"facebookAccessToken"`
	GitHubAccessToken   string    `gorm:"size:255"        json:"githubAccessToken"`
	EmailAccessToken    string    `gorm:"size:255"        json:"emailAccessToken"`
	RefreshToken        string    `gorm:"size:255"        json:"refreshToken"`
	Name                string    `gorm:"size:255"        json:"name"`
	Email               string    `gorm:"size:255;unique" json:"email"`
	Password            []byte    `gorm:"size:255"        json:"-"`
	Role                string    `gorm:"size:50"         json:"role"`
	IPAddress           string    `gorm:"size:45"         json:"-"`
	UserAgent           string    `gorm:"size:255"        json:"-"`
	CreatedAt           time.Time `gorm:"autoCreateTime"  json:"-"`
	UpdatedAt           time.Time `gorm:"autoUpdateTime"  json:"-"`
	LastLoginAt         time.Time `gorm:"autoUpdateTime"  json:"-"`
	ExpiresAt           time.Time `gorm:"autoUpdateTime"  json:"expiresAt"`
	IsActive            bool      `gorm:"default:true"    json:"isActive"`
	ProfilePictureURL   string    `gorm:"size:255"        json:"profilePictureUrl"`
	PhoneNumber         string    `gorm:"size:20"         json:"-"`
	Address             string    `gorm:"size:255"        json:"address"`
	TwoFactorEnabled    bool      `gorm:"default:false"   json:"twoFactorEnabled"`
}

// OAuth
