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
		logrus.Errorf("Password comparison failed: %v", err)

		return HandleErr(ctx, fiber.StatusUnauthorized, "Incorrect Password", nil)
	}

	// Update the user's JWT token and auth method
	user.AccessToken = []byte(ctx.Cookies("jwt"))
	if user.AuthMethod == "" {
		user.AuthMethod = "jwt"
	}

	// Save the updated user information in the database.
	if err := database.GetDB().Save(&user).Error; err != nil {
		logrus.Errorf("Failed to save user data: %v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to save user data", err)
	}

	// ctx.Cookie(&fiber.Cookie{Name: "auth_method", Value: "jwt"})
	// ctx.Cookie(&fiber.Cookie{Name: "user_id", Value: strconv.FormatUint(uint64(user.ID), 10)})
	// ctx.Cookie(&fiber.Cookie{Name: "user_email", Value: user.Email})

	// Set the auth method and user ID in the context.
	// ctx.Locals("auth_method", "jwt")
	// ctx.Locals("user_id", user.ID)
	// ctx.Locals("user_email", user.Email)

	if err := generateJWTAndSetCookie(ctx, cfg, user.ID); err != nil {
		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to generate JWT and set cookie", err)
	}

	logrus.Infof("------ Login User.struct Debug ------")
	logrus.Infof("User logged in with ID: %d", user.ID)
	// logrus.Infof("%+v", fiber.Cookie{Name: "session", Value: "session_value"})
	logrus.Infof("Email: %s", user.Email)
	logrus.Infof("JWT: %s", user.AccessToken)
	logrus.Infof("Auth method: %s", user.AuthMethod)
	logrus.Infof("------ ctx.Cookies Debug ------")
	logrus.Infof("User logged in with ID: %s", ctx.Cookies("user_id"))
	// logrus.Infof("session: %s", ctx.Cookies("session")) // TODO unable to retrieve session value
	logrus.Infof("Email: %s", ctx.Cookies("user_email"))
	logrus.Infof("JWT: %s", ctx.Cookies("jwt"))
	logrus.Infof("Auth method: %s", ctx.Cookies("auth_method"))
	logrus.Infof("------ Mysql Debug ------")
	logrus.Infof("")

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
	logrus.Infof("------ Logout ------")

	userEmail := ctx.Cookies("user_email")
	logrus.Infof("DB Email: %v", userEmail)

	var user models.User

	authMethod := ctx.Cookies("auth_method")
	logrus.Infof("DB Auth method: %s", authMethod)

	// Retrieve the session value
	session := ctx.Cookies("session")
	logrus.Infof("Session value: %s", session)

	if err := database.GetDB().Where("email = ?", userEmail).First(&user).Error; err != nil {
		logrus.Errorf("User not found during logout: %v", err)

		return HandleErr(ctx, fiber.StatusNotFound, "User not found", err)
	}

	if authMethod == "" {
		logrus.Warn("auth_method not set in context, proceeding with logout")
	} else {
		logrus.Infof("Logout initiated for auth method: %v", authMethod)
	}

	jwtToken := ctx.Cookies("jwt")
	if jwtToken == "" {
		logrus.Warn("JWT token not found in cookies, cannot proceed with logout")

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "JWT token not found"}))
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})
	logrus.Info("JWT cookie cleared")

	if authMethod != "" {
		if err := HandleLogoutByAuthMethod(ctx, cfg, authMethod); err != nil {
			return err
		}
	} else {
		logrus.Warn("No auth method provided, skipping specific logout handling")
	}

	logrus.Infof("JWT token found: %s", jwtToken)
	logrus.Infof("session: %s", session) // Log the session value

	if authMethod != "" {
		logrus.Infof("Auth method: %s", authMethod)
	}

	// Clear the auth method and access token
	user.AuthMethod = ""
	user.AccessToken = nil
	user.IsActive = false

	// Save the updated user information
	if err := database.GetDB().Save(&user).Error; err != nil {
		logrus.Errorf("Failed to clear user data during logout: %v", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to clear user data", err)
	}

	if err := ctx.Redirect("/auth"); err != nil {
		logrus.Error("Failed to redirect: ", err)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	return nil
}

/* return fmt.Errorf %w ctx.Status(fiber.Status).JSON(fiber.Map{}
    dont delete this.
	logrus.Infof("------ Logout Process Debug ------")
	logrus.Infof("User id: %v", userID)
	logrus.Infof("Email: %v", userEmail)
	logrus.Infof("JWT token found: %s", jwtToken)
	logrus.Infof("Auth method: %s", authMethod)
	logrus.Infof("sesion: %s", ctx.Cookies("session"))
*/
