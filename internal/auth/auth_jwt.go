package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/logrus"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

func genJWTCookie(ctx *fiber.Ctx, cfg *config.Config, name string) error {
	logrus.Debugf("--- genJWTCookie s ---")

	// *Create the JWT claims
	claims := models.JwtClaims{
		Issuer:     name,
		Purpose:    "Go-Auth",
		Audience:   "Go-Auth_User",
		AuthMethod: "Email",
		Role:       "User",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenED)),
			Subject:   name, // Use the email user ID as the subject
		},
	}

	// *Generate the JWT token
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(cfg.JWTSecretKey)
	if err != nil {
		logrus.Errorf("Could not generate JWT: 🟢%v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Could not generate JWT", err)
	}

	logrus.Infof("Generated JWT token for user 🔵Name 🟢%s", name)
	logrus.Infof("🔵JWT token:🟢🗝️%s", token)

	// *Generate a new refresh token
	refreshToken := genRefreshTkn(name)
	logrus.Infof("Generated 🔵 Refresh_token: 🟢🗝️%s", refreshToken)

	// *Store the refresh token in the database
	if err := strRefreshTkn(name, refreshToken); err != nil {
		logrus.Errorf("Failed to store refresh token: 🟢%v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Could not store refresh token", err)
	}

	logrus.Infof("Generated JWT token for user 🔵Name 🟢%s", name)

	// *Set the JWT token outgoing response.
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(TokenED),
		HTTPOnly: true,
		Secure:   false, // Only for Development.
	})

	// *Store JWT from request.
	JWT := ctx.Cookies("jwt")
	if JWT == "" {
		return HandleErr(ctx, fiber.StatusUnauthorized, "Token not found", nil)
	}

	// *Parse and validate the JWT token
	if err := ParseJWT(ctx, cfg, "GenJWT"); err != nil {
		logrus.Errorf("Failed to parse and validate JWT: 🟢%v", err)

		return HandleErr(ctx, fiber.StatusUnauthorized, "Invalid token", err)
	}

	logrus.Infof("🔵JWT secret key: 🟢%s", cfg.JWTSecretKey) // Assuming cfg.JWTSecretKey holds the key

	return nil
}

func strRefreshTkn(name, refreshToken string) error {
	logrus.Debugf("--- strRefreshTkn - > - Retrieve existing session ---")

	// *Retrieve the existing session from the database
	var usrsession models.UsrSession
	if err := database.GetDB().Where("name = ?", name).First(&usrsession).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle the case where no session exists
			return fmt.Errorf("no existing session found for name: 🟢%s", name)
		}

		return fmt.Errorf("failed to retrieve existing session: 🟢%w", err)
	}

	// logrus.Infof("User retrieved from DB: 🟢%+v", usrsession)
	logrus.InfoFields(usrsession, "User Retrieved from DB 🔷strRefreshTkn",
		"Role",
		"Email",
		"Name",
		"Provider",
		"IsActive",
		"EmailAccessToken",
		"RefreshToken🗝️",
		"EmailUserID",
		"ExpiresAt",
	)

	// *Update the existing session with the new refresh token and expiration
	usrsession.RefreshToken = refreshToken
	usrsession.ExpiresAt = time.Now().Add(TokenED) // Set expiration as needed

	logrus.Debugf("----  Save 2 fields in the session table - > - RefreshToken, ExpiresAt. ----")

	if err := database.GetDB().Model(&usrsession).
		Where("name = ?", name).
		Updates(models.UsrSession{
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(TokenED),
		}).Error; err != nil {
		return fmt.Errorf("failed to update refresh token: 🟢%w", err)
	}

	return nil
}

func genRefreshTkn(name string) string {
	logrus.Debugf("--- genRefreshTkn s ---")

	// *Generate a unique refresh token.
	refreshToken := fmt.Sprintf("refresh-token-for-%s-%d", name, time.Now().UnixNano())

	return refreshToken
}
