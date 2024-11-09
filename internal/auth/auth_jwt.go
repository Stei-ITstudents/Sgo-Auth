package auth

import (
	"fmt"
	"time"

	"errors"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/logrus"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

type CustomClaims struct {
	Issuer     string `json:"iss"`
	Purpose    string `json:"purpose"`
	Audience   string `json:"aud"`
	AuthMethod string `json:"authMethod"`
	jwt.RegisteredClaims
}

// ᐅ ➽

func genJWTCookie(ctx *fiber.Ctx, cfg *config.Config, emailUserID string) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- genJWTCookie s ---")

	// *Create the JWT claims
	claims := CustomClaims{
		Issuer:     "CristyNel",
		Purpose:    "Go-Auth",
		Audience:   "Go-Auth_User",
		AuthMethod: "Email",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenED)),
			Subject:   emailUserID, // Use the email user ID as the subject
		},
	}

	// *Generate the JWT token
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(cfg.JWTSecretKey)
	if err != nil {
		logrus.Errorf("Could not generate JWT: ➽%v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Could not generate JWT", err)
	}

	logrus.Infof("Generated JWT token for user ᐅ Email ➽%s", emailUserID)
	logrus.Info("ᐅJWT token: ➽", token)

	// *Generate a new refresh token
	refreshToken := genRefreshTkn(emailUserID)
	logrus.Infof("Generated ᐅ Refresh_token: ➽%s", refreshToken)

	// *Store the refresh token in the database
	if err := strRefreshTkn(emailUserID, refreshToken); err != nil {
		logrus.Errorf("Failed to store refresh token: ➽%v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Could not store refresh token", err)
	}

	logrus.Infof("Generated JWT token for user ᐅ ID ➽%s", emailUserID)

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
		logrus.Errorf("Failed to parse and validate JWT: ➽%v", err)

		return HandleErr(ctx, fiber.StatusUnauthorized, "Invalid token", err)
	}

	logrus.Infof("ᐅJWT secret key: ➽%s", cfg.JWTSecretKey) // Assuming cfg.JWTSecretKey holds the key

	return nil
}

func strRefreshTkn(emailUserID, refreshToken string) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- strRefreshTkn - > - Retrieve existing session ---")

	var usrsession models.UsrSession
	if err := database.GetDB().Where("email_user_id = ?", emailUserID).First(&usrsession).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle the case where no session exists
			return fmt.Errorf("no existing session found for email user ID: ➽%s", emailUserID)
		}

		return fmt.Errorf("failed to retrieve existing session: ➽%w", err)
	}

	// logrus.Infof("User retrieved from DB: ➽%+v", usrsession)
	logrus.InfoFields(usrsession, "User Retrieved from DB ⊛strRefreshTkn",
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

	// Update the existing session with the new refresh token and expiration
	usrsession.RefreshToken = refreshToken
	usrsession.ExpiresAt = time.Now().Add(TokenED) // Set expiration as needed

	logrus.Debugf("----  Save 2 fields in the session table - > - RefreshToken, ExpiresAt. ----")

	if err := database.GetDB().Model(&usrsession).
		Where("email_user_id = ?", emailUserID).
		Updates(models.UsrSession{
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(TokenED),
		}).Error; err != nil {
		return fmt.Errorf("failed to update refresh token: ➽%w", err)
	}

	return nil
}

func genRefreshTkn(emailUserID string) string { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- genRefreshTkn s ---")

	// Generate a unique refresh token (you might want to use a more secure method)
	refreshToken := fmt.Sprintf("refresh-token-for-%s-%d", emailUserID, time.Now().UnixNano())

	return refreshToken
}

func getRefreshTkn(emailUserID string) (string, error) { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- getRefreshTkn s ---")

	var session models.UsrSession
	if err := database.GetDB().Where("email_user_id = ?", emailUserID).First(&session).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve refresh token: ➽%w", err)
	}

	return session.RefreshToken, nil
}

func hndJWTLogout(ctx *fiber.Ctx) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- hndJWTLogout s ---")

	jwtToken := ctx.Cookies("jwt")
	if jwtToken == "" {
		logrus.Warn("JWT token not found in cookies, cannot proceed with logout")

		return HandleErr(ctx, fiber.StatusUnauthorized, "JWT token not found", nil)
	}

	logrus.Infof("JWT token found: ➽%s", jwtToken)

	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})
	logrus.Info("JWT cookie cleared")

	EmailUserID := ctx.Locals("user_id")
	if EmailUserID != nil {
		logrus.Infof("User with ID ➽%v logged out.", EmailUserID)

		emailUserID, ok := EmailUserID.(string)
		if !ok {
			logrus.Error("Failed to assert user ID as string")

			return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to assert user ID", nil)
		}

		if err := delRefreshTkn(emailUserID); err != nil {
			logrus.Errorf("Failed to delete refresh token: ➽%v", err)
		}
	}

	if err := ctx.Redirect("/auth"); err != nil {
		logrus.Error("Failed to redirect: ", err)

		return fmt.Errorf("failed to redirect: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	return nil
}

func delRefreshTkn(emailUserID string) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- delRefreshTkn s ---")

	if err := database.GetDB().Where("email_user_id = ?", emailUserID).Delete(&models.UsrSession{}).Error; err != nil {
		return fmt.Errorf("failed to delete refresh token: ➽%w", err)
	}

	return nil
}
