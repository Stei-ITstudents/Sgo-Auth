package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	SecretKey  = "jwt_secret"
	BcryptCost = 14
	TokenED    = 24 * time.Hour // expiration duration
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

func checkUserExists(email string) (bool, error) {
	var existingUser models.User
	err := database.GetDB().Where("email = ?", email).First(&existingUser).Error

	if err == nil {
		logrus.Warn("Email already exists: ", email)

		return true, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		logrus.Error("Error checking if user exists: ", err)

		return false, err
	}

	return false, nil
}

func createUser(user *models.User) error {
	err := database.GetDB().Create(user).Error
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			logrus.Warn("Duplicate entry error: ", err)

			return errors.New("email already exists")
		}

		return err
	}

	return nil
}

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

func User(ctx *fiber.Ctx, cfg *config.Config) error {
	cookie := ctx.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return cfg.JWTSecretKey, nil // Use cfg to access JWTSecretKey
	})
	// return jwt token with claims
	if err != nil {
		return fmt.Errorf("unauthenticated: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"}))
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("unauthenticated: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"}))
	}

	var user models.User

	if err := database.GetDB().Where("id = ?", claims.Issuer).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w",
			ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"}))
	}

	if err := ctx.JSON(user); err != nil {
		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to send JSON response"}))
	}

	return nil
}

func UpdateUser(ctx *fiber.Ctx) error {
	userID := ctx.Params("id")

	var data map[string]string

	if err := ctx.BodyParser(&data); err != nil {
		return fmt.Errorf("invalid request body: %w",
			ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"}))
	}

	var user models.User

	if err := database.GetDB().First(&user, userID).Error; err != nil || user.ID == 0 {
		return fmt.Errorf("user not found: %w",
			ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"}))
	}

	user.Name = data["name"]
	user.Email = data["email"]

	if err := database.GetDB().Save(&user).Error; err != nil {
		return fmt.Errorf("could not update user: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not update user"}))
	}

	if err := ctx.JSON(fiber.Map{"message": "User updated successfully"}); err != nil {
		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to send JSON response"}))
	}

	return nil
}

func Logout(ctx *fiber.Ctx, cfg *config.Config) error {
	authMethod := ctx.Locals("auth_method")
	ctx.ClearCookie("session_id")

	if authMethod == "github" {
		accessToken := ctx.Locals("access_token")

		// Assert the type of accessToken
		accessTokenStr, ok := accessToken.(string)
		if !ok {
			return fmt.Errorf("failed to process access token: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid access token type"}))
		}

		revokeTokenURL := "https://api.github.com/applications/" + cfg.OAuth.GithubClientID + "/tokens/" + accessTokenStr

		req, err := http.NewRequestWithContext(ctx.Context(), http.MethodDelete, revokeTokenURL, nil) // Use http.MethodDelete
		if err != nil {
			return fmt.Errorf("failed to create revoke request: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create revoke request"}))
		}

		req.SetBasicAuth(cfg.OAuth.GithubClientID, cfg.OAuth.GithubClientSecret)

		client := &http.Client{}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to revoke token: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to revoke token: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
		}
	}

	// Clear the JWT cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})

	// Optionally: Log the logout action
	userID := ctx.Locals("user_id")
	if userID != nil {
		logrus.Infof("User with ID %v logged out.", userID)
	}

	// Redirect to the authentication page
	if err := ctx.Redirect("/auth"); err != nil {
		return fmt.Errorf("failed to redirect: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	return nil
}

func GetUsers(ctx *fiber.Ctx) error {
	var users []models.User
	if err := database.GetDB().Find(&users).Error; err != nil {
		return fmt.Errorf("failed to retrieve users: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve users"}))
	}

	logrus.WithFields(logrus.Fields{
		"users": users,
	}).Info("Users response")

	if err := ctx.JSON(users); err != nil {
		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send JSON response"}))
	}

	return nil
}

func DeleteUser(ctx *fiber.Ctx) error {
	userID := ctx.Params("id")
	if err := database.GetDB().Delete(&models.User{ID: 0, Name: "", Email: "", Password: nil}, userID).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"}))
	}

	if err := ctx.JSON(fiber.Map{"message": "User deleted successfully"}); err != nil {
		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send JSON response"}))
	}

	return nil
}

// return fmt.Errorf %w ctx.Status(fiber.Status).JSON(fiber.Map{}
