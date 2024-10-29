package middleware

import (
	"fmt"

	"github.com/go-auth/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// ConfigMiddleware injects the config into the context.
func ConfigMiddleware(cfg *config.Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		ctx.Locals("config", cfg)

		if err := ctx.Next(); err != nil {
			return fmt.Errorf("Error: %w", err)
		}

		return nil
	}
}

// AuthMiddleware creates a middleware for JWT authentication.
func AuthMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Retrieve the config from context
		cfg := ctx.Locals("config")
		if cfg == nil {
			return fmt.Errorf("internal server error: config not found: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error: config not found"}))
		}

		// Assert the type of cfg
		config, ok := cfg.(*config.Config)
		if !ok {
			return fmt.Errorf("internal server error: invalid config type: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error: invalid config type"}))
		}

		// Initialize tokenString in a separate variable
		tokenString := ctx.Cookies("jwt")
		if tokenString == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid access token type: %w",
					ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid access token type"}))
			}

			return config.JWTSecretKey, nil // Access secret key from config
		})
		if err != nil {
			return fmt.Errorf("failed to parse token: %w",
				ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Failed to parse token"}))
		}

		// Validate the token
		if !token.Valid {
			logrus.Error("Invalid token")

			return fmt.Errorf("unauthorized: %w",
				ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"}))
		}

		return ctx.Next()
	}
}
