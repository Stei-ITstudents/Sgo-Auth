package models

import (
	"time"

	"github.com/go-auth/logrus"
	"gorm.io/gorm"
)

const TokenED = 15 * time.Minute

type UsrSession struct { // $➮🗝️ᐅ➽⊛
	Provider            string    `gorm:"size:50"             json:"provider,omitempty"`
	GoogleUserID        string    `gorm:"size:255"            json:"googleUserId,omitempty"`
	FacebookUserID      string    `gorm:"size:255"            json:"facebookUserId,omitempty"`
	GitHubUserID        string    `gorm:"size:255"            json:"githubUserId,omitempty"`
	EmailUserID         string    `gorm:"size:255"            json:"emailUserId,omitempty"`
	GoogleAccessToken   string    `gorm:"size:255"            json:"googleAccessToken,omitempty"`
	FacebookAccessToken string    `gorm:"size:255"            json:"facebookAccessToken,omitempty"`
	GitHubAccessToken   string    `gorm:"size:255"            json:"githubAccessToken,omitempty"`
	EmailAccessToken    string    `gorm:"size:255"            json:"emailAccessToken,omitempty"`
	RefreshToken        string    `gorm:"size:255"            json:"refreshToken,omitempty"`
	Name                string    `gorm:"size:255"            json:"name"`
	Email               string    `gorm:"size:255;unique"     json:"email,omitempty"`
	Password            []byte    `gorm:"size:255"            json:"-"`
	Role                string    `gorm:"size:50"             json:"role,omitempty"`
	IPAddress           string    `gorm:"size:45"             json:"-"`
	UserAgent           string    `gorm:"size:255"            json:"-"`
	CreatedAt           time.Time `gorm:"autoCreateTime"      json:"-"`
	UpdatedAt           time.Time `gorm:"autoUpdateTime"      json:"-"`
	LastLoginAt         time.Time `gorm:"autoUpdateTime"      json:"lastLoginAt,omitempty"`
	ExpiresAt           time.Time `json:"expiresAt,omitempty"`
	IsActive            bool      `gorm:"default:true"        json:"isActive,omitempty"`
	ProfilePictureURL   string    `gorm:"size:255"            json:"profilePictureUrl,omitempty"`
	PhoneNumber         string    `gorm:"size:20"             json:"-"`
	Address             string    `gorm:"size:255"            json:"address,omitempty"`
	TwoFactorEnabled    bool      `gorm:"default:false"       json:"twoFactorEnabled,omitempty"`
}

// BeforeCreate is a GORM hook that sets the ExpiresAt field before creating a new record.
func (session *UsrSession) BeforeCreate(_ *gorm.DB) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- BeforeCreate - > - Set ExpiresAt field ---")

	session.ExpiresAt = time.Now().Add(TokenED)
	logrus.Infof("ExpiresAt: ➽%v", session.ExpiresAt)

	return nil
}
