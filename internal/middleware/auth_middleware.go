package middleware

import (
	"fmt"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/logrus"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// *ConfigMiddleware injects the config into the context.
func ConfigMiddleware(cfg *config.Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		logrus.Infof("• Injecting 🔵Caarlos0 config: 🟢🗝️%+v", cfg)
		ctx.Locals("config", cfg)

		if err := ctx.Next(); err != nil {
			return fmt.Errorf("error: 🟢%w", err)
		}

		return nil
	}
}

func AuthMiddleware() fiber.Handler {
	logrus.Debugf("--- AuthMiddleware s ---")

	return func(ctx *fiber.Ctx) error {
		// *Retrieve the config from context
		cfg := ctx.Locals("config")
		if cfg == nil {
			return ctx.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"error": "Internal server error: config not found"})
		}

		// *Assert the type of cfg
		config, ok := cfg.(*config.Config)
		if !ok {
			return ctx.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"error": "Internal server error: invalid config type"})
		}

		// *Initialize tokenString in a separate variable
		tokenString := ctx.Cookies("jwt")
		if tokenString == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}

		// *Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, nil // Returning nil to allow the error handling below
			}

			return config.JWTSecretKey, nil // Access secret key from config
		})
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Failed to parse token"})
		}

		// *Validate the token
		if !token.Valid {
			logrus.Error("Invalid token")

			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}

		return ctx.Next()
	}
}
