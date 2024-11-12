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
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ➮🗝️ᐅ➽⊛

const (
	Split2     = 2
	SecretKey  = "jwt_secret"
	BcryptCost = 14
	TokenED    = 20 * time.Minute
	RoleUser   = "user"
	RoleAdmin  = "admin"
)

func Register(ctx *fiber.Ctx) error {
	logrus.Debugf("--- Register s ---")

	// *Parse request body from the context
	data, err := parseRequestBody(ctx)
	if err != nil {
		logrus.Error("Invalid request body: ", err)

		return HandleErr(ctx, fiber.StatusBadRequest, "Invalid request body", err)
	}

	logrus.Infof("Data: 🟢%+v", data)

	// *Retrieve IP address and user agent.
	ipAddress := ctx.IP()
	userAgent := ctx.Get("User-Agent")
	logrus.Infof("--- Registering 🔵IP Address: 🟢%s 🔵User Agent: 🟢%s", ipAddress, userAgent)

	// *Check if the user already exists
	logrus.Infof("Checking if user exists with email: 🟢%s", data["email"])
	exists, err := checkUserExists(data["email"])

	if err != nil {
		logrus.Error("Error checking if user exists: ", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Internal Server Error", err)
	}

	if exists {
		return HandleErr(ctx, fiber.StatusConflict, "Email already exists", nil)
	}

	// *Generate hashed password.
	logrus.Infof("Generating password for user: 🟢%s", data["username"])
	password, err := bcrypt.GenerateFromPassword([]byte(data["password"]), BcryptCost)

	if err != nil {
		logrus.Error("Password generation failed: ", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Internal Server Error", err)
	}

	// *Create new user.
	usrsession := models.UsrSession{
		Provider:         "email", // Set as needed
		EmailUserID:      data["email"],
		RefreshToken:     genRefreshTkn(data["email"]),
		Name:             data["username"],
		Email:            data["email"],
		Password:         password,
		Role:             RoleUser,
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
		ExpiresAt:        time.Now().Add(TokenED),
		IsActive:         true,
		TwoFactorEnabled: false,
	}

	if err := createUser(&usrsession); err != nil {
		logrus.Error("User creation failed: ", err)

		return HandleErr(ctx, fiber.StatusConflict, "Email already exists", err)
	}

	logrus.InfoFields(usrsession, "User registered with 🟡Register",
		"Role",
		"Email",
		"Name",
		"Provider",
		"Password🗝️",
	)

	if err := ctx.JSON(usrsession); err != nil {
		return fmt.Errorf("failed to send JSON response: 🟢%w", err)
	}

	return nil
}

func Login(ctx *fiber.Ctx, cfg *config.Config) error {
	logrus.Debugf("🟡️--- Login s ---")
	// *Parse request body.
	data, err := parseRequestBody(ctx)
	if err != nil {
		return HandleErr(ctx, fiber.StatusBadRequest, "Invalid request body", err)
	}

	// logrus.Infof("Parsed request Body 🔵Data: 🟢%+v", data)
	logrus.InfoFields(data, "Parsed request Body 🔵Data: 🔷Login",
		"username",
		"email",
		"password🗝️",
	)

	// *Retrieve the user session from the database.
	var usrsession models.UsrSession
	if err := database.GetDB().
		Where("email = ?", data["email"]).
		First(&usrsession).Error; err != nil {
		// Check if the error is due to record not found
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return HandleErr(ctx, fiber.StatusNotFound, "User not found", nil)
		}
		// Handle other potential database errors
		return HandleErr(ctx, fiber.StatusInternalServerError, "Database error", err)
	}

	// logrus.Infof("User retrieved from DB: 🟢%+v", usrsession)
	logrus.InfoFields(usrsession, "User Retrieved from DB 🔷Login",
		"Role",
		"Email",
		"Name",
		"Provider",
		"EmailAccessToken",
		"RefreshToken🗝️",
		"Password🗝️",
	)

	// *Check if EmailUserID is empty or zero.
	if usrsession.EmailUserID == "" { // or usrsession.EmailUserID == 0 if it's an integer type
		return HandleErr(ctx, fiber.StatusNotFound, "User not found", nil)
	}

	// *Validate the password.
	if err := bcrypt.CompareHashAndPassword(usrsession.Password, []byte(data["password"])); err != nil {
		logrus.Errorf("Password comparison failed: 🟢%v", err)

		return HandleErr(ctx, fiber.StatusUnauthorized, "Incorrect Password", nil)
	}

	// *generate JWT token and set cookie
	if err := genJWTCookie(ctx, cfg, usrsession.Name); err != nil { // Directly use EmailUserID here
		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to generate JWT and set cookie", err)
	}

	// *Update UsrSession fields
	// logrus.Infof("JWT: 🟢🗝️%s", JWT)
	logrus.Infof("EmailAccessToken: 🟢🗝️%s", usrsession.EmailAccessToken)

	usrsession.RefreshToken = "Test if saving works"
	// usrsession.RefreshToken = genRefreshTkn(usrsession.EmailUserID)
	usrsession.LastLoginAt = time.Now()
	usrsession.Provider = "email"
	usrsession.EmailUserID = usrsession.Email
	usrsession.EmailAccessToken = ctx.Cookies("jwt")

	// *Save updated UsrSession
	if err := UpdateUser(ctx); err != nil {
		logrus.Error("Failed to update user session: ", err)

		return HandleErr(ctx, fiber.StatusInternalServerError, "Failed to log in", err)
	}

	logrus.InfoFields(usrsession, "User After save from DB 🔷Login",
		"Role",
		"Email",
		"Name",
		"Provider",
		"IsActive",
		"EmailAccessToken🗝️",
		"RefreshToken🗝️",
		"EmailUserID",
		"ExpiresAt",
	)

	// GetHeader(ctx, "-- The login")

	if err := ctx.JSON(fiber.Map{
		"message":  "success",
		"redirect": "/index.html",
	}); err != nil {
		return fmt.Errorf("failed to send JSON response: 🟢%w", err)
	}

	logrus.Debugf("🟡️--- Login e ---")

	return nil
}

func HandleLogoutByProvider(ctx *fiber.Ctx, cfg *config.Config, usrsession models.UsrSession) error { // ➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleLogoutByProvider s ---")

	switch usrsession.Provider {
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
	case "email":

	default:
		logrus.Warnf("Unsupported provider: 🟢%v", usrsession.Provider)

		return fmt.Errorf("unsupported provider: 🟢%v", usrsession.Provider)
	}

	return nil
}

func Logout(ctx *fiber.Ctx, cfg *config.Config) error {
	logrus.Debugf("--- Logout s ---")

	// *Retrieve JWT from the cookie
	jwtToken := ctx.Cookies("jwt")
	if jwtToken == "" {
		logrus.Errorf("JWT token missing in cookie")

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"}))
	}

	// *Parse the JWT to extract claims
	token, err := jwt.ParseWithClaims(jwtToken, &models.JwtClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return (cfg.JWTSecretKey), nil
	})

	if err != nil || !token.Valid {
		logrus.Errorf("Invalid or expired token: %v", err)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"}))
	}

	// *Assert claims as *CustomClaims to access Subject and AuthMethod
	claims, ok := token.Claims.(*models.JwtClaims)
	if !ok {
		logrus.Error("Failed to parse claims")

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Claims parsing error"}))
	}

	// *Log the subject (user ID or email) and authentication method
	// logrus.Infof("From claims data: 🟢%+v", claims
	logrus.InfoFields(claims, "From claims data: 🔷Logout",
		"Issuer",
		"Purpose",
		"Audience",
		"Subject",
		"AuthMethod",
	)

	// *Invalidate the JWT by setting its expiration to the past
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",                              // Clear the value
		Expires:  time.Now().Add(-24 * time.Hour), // Expired in the past
		HTTPOnly: true,
		Secure:   true, // Set to true if using HTTPS
		SameSite: fiber.CookieSameSiteStrictMode,
	})

	// *Retrieve and update the user session in the database
	if err := database.GetDB().
		Model(&models.UsrSession{}).
		Where("email = ?", claims.Subject).
		Updates(map[string]interface{}{
			"refresh_token":      "",
			"provider":           "",
			"email_access_token": "",
			"is_active":          false,
		}).Error; err != nil {
		// Check if the error is due to record not found
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return HandleErr(ctx, fiber.StatusNotFound, "User not found", nil)
		}
		// Handle other potential database errors
		return HandleErr(ctx, fiber.StatusInternalServerError, "Database error", err)
	}

	// *Clear the JWT cookie to log the user out
	ctx.ClearCookie("jwt")

	// *Redirect to the login page
	if err := ctx.Redirect("/auth"); err != nil {
		logrus.Error("Failed to redirect: ", err)

		return fmt.Errorf("failed to send JSON response: 🟢%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to redirect"}))
	}

	// *Return success response
	if err := ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "Logout successful",
		"redirect": "/auth",
	}); err != nil {
		logrus.Error("Failed to send JSON response: ", err)

		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}
