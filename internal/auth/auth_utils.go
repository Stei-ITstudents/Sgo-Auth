package auth

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// Page handles the rendering of the authentication page.
func Page(ctx *fiber.Ctx) error {
	if err := ctx.SendFile("web/auth.html"); err != nil {
		return fmt.Errorf("failed to send auth page: %w", err)
	}

	return nil
}

func parseRequestBody(ctx *fiber.Ctx) (map[string]string, error) {
	var data map[string]string
	if err := ctx.BodyParser(&data); err != nil {
		return nil, fmt.Errorf("error parsing request body: %w", err)
	}

	return data, nil
}

// HandleErr sends a JSON error response with a status code, message, and optional error details.
func HandleErr(ctx *fiber.Ctx, status int, message string, err error) error {
	response := fiber.Map{
		"error":   message,
		"status":  status,
		"details": nil,
	}

	if err != nil {
		logrus.Error(err)
		response["details"] = err.Error()
	}

	if jsonErr := ctx.Status(status).JSON(response); jsonErr != nil {
		logrus.Error("Failed to send JSON response: ", jsonErr)

		return fmt.Errorf("failed to send JSON response: %w", jsonErr)
	}

	return nil
}
