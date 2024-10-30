package auth

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

func generateJWTAndSetCookie(ctx *fiber.Ctx, cfg *config.Config, userID uint) error {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    strconv.FormatUint(uint64(userID), 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenED)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})
	token, err := claims.SignedString(cfg.JWTSecretKey) // Use cfg to access JWTSecretKey

	if err != nil {
		return fmt.Errorf("could not generate JWT: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate JWT"}))
	}

	logrus.Infof("Generated token: %s", token)

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(TokenED),
		HTTPOnly: true,
		MaxAge:   int(TokenED.Seconds()),
		Secure:   true,
	}
	ctx.Cookie(&cookie)

	return nil
}

func HandleJWTLogout(ctx *fiber.Ctx) error {
	// Step 1: Retrieve the JWT Token from Cookies
	jwtToken := ctx.Cookies("jwt")
	if jwtToken == "" {
		logrus.Warn("JWT token not found in cookies, cannot proceed with logout")

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "JWT token not found"}))
	}

	logrus.Infof("JWT token found: %s", jwtToken)

	// Clear the JWT cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})
	logrus.Info("JWT cookie cleared")

	// Optionally: Log the logout action
	userID := ctx.Locals("user_id")
	if userID != nil {
		logrus.Infof("User with ID %v logged out.", userID)
	}

	// Redirect to the authentication page
	if err := ctx.Redirect("/auth"); err != nil {
		logrus.Error("Failed to redirect: ", err)

		return fmt.Errorf("failed to redirect: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	return nil
}
