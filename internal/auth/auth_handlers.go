package auth

import (
	"fmt"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	SecretKey  = "jwt_secret"
	BcryptCost = 14
	TokenED    = 24 * time.Hour // expiration duration
)

func Register(ctx *fiber.Ctx) error {
	data, err := parseRequestBody(ctx)
	if err != nil {
		logrus.Error("Invalid request body: ", err)

		return HandleErr(ctx, fiber.StatusBadRequest, "Invalid request body", err)
	}

	// Check if the user already exists
	exists, err := checkUserExists(data["email"])
	if err != nil {
		logrus.Error("Error checking if user exists: ", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Internal Server Error", err)
	}

	if exists {
		logrus.Warn("Email already exists: ", data["email"])

		return HandleErr(ctx, fiber.StatusConflict, "Email already exists", nil)
	}

	// Generate hashed password
	password, err := bcrypt.GenerateFromPassword([]byte(data["password"]), BcryptCost)
	if err != nil {
		logrus.Error("Password generation failed: ", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Internal Server Error", err)
	}

	// Create new user
	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
	}
	if err := createUser(&user); err != nil {
		logrus.Error("User creation failed: ", err)

		return HandleErr(ctx, fiber.StatusConflict, "Email already exists", err)
	}

	logrus.Infof("User registered with ID: %d", user.ID)

	if err := ctx.JSON(user); err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

func Login(ctx *fiber.Ctx, cfg *config.Config) error {
	data, err := parseRequestBody(ctx)
	if err != nil {
		return HandleErr(ctx, fiber.StatusBadRequest, "Invalid request body", err)
	}

	var user models.User

	if err := database.GetDB().Where("email = ?", data["email"]).First(&user).Error; err != nil || user.ID == 0 {
		return HandleErr(ctx, fiber.StatusNotFound, "User not found", err)
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		// Log the detailed error for debugging purposes
		logrus.Errorf("Password comparison failed: %v", err)
		// Return a generic error message to the user
		return HandleErr(ctx, fiber.StatusUnauthorized, "Incorrect Password", nil)
	}

	if err := generateJWTAndSetCookie(ctx, cfg, user.ID); err != nil {
		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to generate JWT and set cookie", err)
	}

	// Return success message and indicate redirection
	if err := ctx.JSON(fiber.Map{
		"message":  "success",
		"redirect": "/index.html",
	}); err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

func HandleLogoutByAuthMethod(ctx *fiber.Ctx, cfg *config.Config, authMethod interface{}) error {
	switch authMethod {
	case "github":
		if err := HandleGithubLogout(ctx, cfg); err != nil {
			logrus.Error("Failed to handle GitHub logout: ", err)

			return err
		}
	case "google":
		if err := HandleGoogleLogout(ctx, cfg); err != nil {
			logrus.Error("Failed to handle Google logout: ", err)

			return err
		}
	case "facebook":
		if err := HandleFacebookLogout(ctx, cfg); err != nil {
			logrus.Error("Failed to handle Facebook logout: ", err)

			return err
		}
	case "jwt", "email":
		// JWT and email logouts are handled by clearing the JWT cookie above
	default:
		logrus.Warnf("Unsupported auth method: %v", authMethod)

		return fmt.Errorf("unsupported auth method: %v", authMethod)
	}

	return nil
}

func Logout(ctx *fiber.Ctx, cfg *config.Config) error {
	authMethod := ctx.Locals("auth_method")
	if authMethod == nil {
		logrus.Warn("auth_method not set in context, proceeding with logout")
	}

	logrus.Infof("Logout initiated for auth method: %v", authMethod)

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

	// Call the appropriate HandleLogout function based on the auth method
	if err := HandleLogoutByAuthMethod(ctx, cfg, authMethod); err != nil {
		return err
	}

	// Optionally: Log the logout action
	userID := ctx.Locals("user_id")
	if userID != nil {
		logrus.Infof("User with ID %v logged out.", userID)
	}

	// Redirect to the authentication page
	if err := ctx.Redirect("/auth"); err != nil {
		logrus.Error("Failed to redirect: ", err)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	logrus.Info("Logout process completed successfully")

	return nil
}

// return fmt.Errorf %w ctx.Status(fiber.Status).JSON(fiber.Map{}
