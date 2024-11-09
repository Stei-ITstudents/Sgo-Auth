package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"

	// "github.com/go-auth/logrus"

	"github.com/go-auth/logrus"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func CreateAdminUser(database *gorm.DB, adminUsername, adminEmail, password string) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- CreateAdminUser s ---")

	// Hash the admin password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logrus.Errorf("Failed to hash password: ➽%v", err)

		return fmt.Errorf("error hashing password: ➽%w", err)
	}

	usrsession := models.UsrSession{
		Provider:            "email",
		GoogleUserID:        "",
		FacebookUserID:      "",
		GitHubUserID:        "",
		EmailUserID:         adminEmail,
		GoogleAccessToken:   "",
		FacebookAccessToken: "",
		GitHubAccessToken:   "",
		EmailAccessToken:    "",
		RefreshToken:        "",
		Name:                adminUsername,
		Email:               adminEmail,
		Role:                RoleAdmin,
		Password:            hashedPassword,
		IPAddress:           "",
		UserAgent:           "",
		ExpiresAt:           time.Now().Add(TokenED),
		IsActive:            true,
		ProfilePictureURL:   "",
		PhoneNumber:         "",
		Address:             "",
		TwoFactorEnabled:    false,
	}

	// Save the admin user session to the database
	if err := database.Create(&usrsession).Error; err != nil {
		logrus.Errorf("Failed to create admin user session: ➽%v", err)

		return err
	}

	logrus.Infof("Admin user created: ➽%s", usrsession.Email)

	return nil
}

func createUser(user *models.UsrSession) error { // $➮🗝️ᐅ➽⊛
	if exists, err := checkUserExists(user.Email); err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	} else if exists {
		return errors.New("user already exists")
	}

	if err := database.GetDB().Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func checkUserExists(email string) (bool, error) { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- checkUserExists s ---")

	var existingUser models.UsrSession
	err := database.GetDB().Where("email = ?", email).First(&existingUser).Error

	if err == nil {
		logrus.Warn("Email already exists: ", email)

		return true, nil // User exists
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logrus.Error("Error checking if user exists: ", err)

		return false, fmt.Errorf("error checking user existence: %w", err)
	}

	return false, nil // User does not exist
}

func User(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- User s ---")

	var user models.UsrSession

	// *Validates JWT using secret key.
	cookie := ctx.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return cfg.JWTSecretKey, nil // Use cfg to access JWTSecretKey
	})

	// logrus.WithFields(logrus.ToFields(cookie)).Infof("User ᐅCookie")
	GetCookies(ctx, "User")

	// *Extracts claims from JWT; checks validity.
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if err != nil || !ok || !token.Valid {
		return fmt.Errorf("unauthenticated: ➽%w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"}))
	}

	logrus.InfoFields(claims, "Claims from cookie JWT ⊛User",
		"Valid",
		"Issuer",
		"Subject",
		"Audience",
		"ExpiresAt",
		"IssuedAt",
		"NotBefore",
		"ID",
	)

	// *Fetch user by email using JWT claims.Issuer from DB.
	if err := database.GetDB().Where("email = ?", claims.Subject).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: ➽%w",
			ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"}))
	}

	logrus.InfoFields(user, "Fetch user, Response ⊛User",
		"Name",
		"Role",
		"Email",
		"IsActive",
		"ExpiresAt",
		"RefreshToken",
		"EmailAccessToken",
		"TwoFactorEnabled",
		"Password🗝️",
	)

	// *Send user as JSON response.
	if err := ctx.JSON(user); err != nil {
		return fmt.Errorf("failed to send JSON response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to send JSON response"}))
	}

	return nil
}

// UpdateUser updates the user session corresponding to the provided email.
func UpdateUser(ctx *fiber.Ctx) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- UpdateUser s ---")

	var (
		data       map[string]string
		usrsession models.UsrSession
	)

	// *Parse request body
	if err := ctx.BodyParser(&data); err != nil {
		return fmt.Errorf("invalid request body: ➽%w",
			ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"}))
	}

	// *Retrieve the user by the Email
	if err := database.GetDB().Where("email = ?", data["email"]).First(&usrsession).Error; err != nil {
		return fmt.Errorf("user not found: ➽%w",
			ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"}))
	}

	logrus.Infof("UpUsr ᐅData: ➽%+v", data)

	// *Update fields
	usrsession.Name = data["username"]
	usrsession.Email = data["email"]

	// *Hash the password if provided
	if password, ok := data["password"]; ok && password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logrus.WithError(err).Error("Failed to hash password")

			return fmt.Errorf("failed to hash password: %w",
				ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Password encryption failed"}))
		}

		usrsession.Password = hashedPassword
	}

	logrus.InfoFields(usrsession, "Updating to DB Data ⊛UpdateUser",
		"Name",
		"Email",
		"Password🗝️",
	)

	// *Update the user session in the database.
	if err := database.GetDB().Model(&usrsession).
		Where("email_user_id = ?", data["email"]).
		Updates(&usrsession).Error; err != nil {
		logrus.Error("Failed to update user: ", err)

		return fmt.Errorf("failed to update user: %w", err)
	}

	// *Send success response.
	if err := ctx.JSON(fiber.Map{"message": "User updated successfully"}); err != nil {
		return fmt.Errorf("failed to send JSON response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to send JSON response"}))
	}

	return nil
}

func GetUsers(ctx *fiber.Ctx) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- GetUsers s ---")

	var users []models.UsrSession

	if err := database.GetDB().Find(&users).Error; err != nil {
		return fmt.Errorf("failed to retrieve users: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve users"}))
	}

	for _, user := range users {
		logrus.InfoFields(user, "Fetch users, Response ⊛GetUsers",
			"Role",
			"Email",
			"IsActive",
			"ExpiresAt",
			"RefreshToken",
			"EmailAccessToken",
			"Password🗝️",
		)
	}

	if err := ctx.JSON(users); err != nil {
		return fmt.Errorf("failed to send JSON response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send JSON response"}))
	}

	return nil
}

func DeleteUser(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- DeleteUser s ---")

	var requestData struct {
		Email    string `json:"email"`
		Password string `json:"password"` // Password for verification
	}

	// *Parse the request body into requestData struct.
	if err := ctx.BodyParser(&requestData); err != nil {
		logrus.Errorf("Error parsing request body: %v", err)

		return fmt.Errorf("invalid request body: ➽%w",
			ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"}))
	}

	logrus.Infof("DelUsr from request ᐅData: ➽%+s", requestData)

	// *Retrieve the user by email.
	var user models.UsrSession
	if err := database.GetDB().Where("email = ?", requestData.Email).First(&user).Error; err != nil {
		logrus.Errorf("User not found: %v", err)

		return fmt.Errorf("user not found: ➽%w",
			ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"}))
	}

	// *Compare the provided password with the stored password (hashed)
	if err := bcrypt.CompareHashAndPassword((user.Password), []byte(requestData.Password)); err != nil {
		logrus.Errorf("Invalid password: %v", err)

		return fmt.Errorf("invalid password: ➽%w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid password"}))
	}

	// *Validates JWT using secret key.
	cookie := ctx.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return cfg.JWTSecretKey, nil // Use cfg to access JWTSecretKey
	})

	// *Error jwt parsing.
	if err != nil || token == nil {
		logrus.Errorf("JWT parsing error: %v", err)

		return fmt.Errorf("invalid token: ➽%w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"}))
	}

	// *Extracts claims from JWT; checks validity.
	_, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		logrus.Errorf("Invalid claims or token: %v", err)

		return fmt.Errorf("unauthenticated: ➽%w",
			ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthenticated"}))
	}

	// // *Log the claims.
	// if err := ParseJWT(ctx, cfg, "Del"); err != nil {
	// 	logrus.Errorf("Failed to parse JWT: %v", err)

	// 	return fmt.Errorf("failed to parse JWT: ➽%w",
	// 		ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Failed to parse JWT"}))
	// }

	// *Delete the user from the database
	if err := database.GetDB().Where("email = ?", requestData.Email).Delete(&models.UsrSession{}).Error; err != nil {
		logrus.Errorf("Failed to delete user: %v", err)

		return fmt.Errorf("failed to delete user: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"}))
	}

	logrus.Infof("User deleted successfully: ➽%s", requestData.Email)

	if err := ctx.Status(fiber.StatusOK).JSON(fiber.Map{"message": "User deleted successfully"}); err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}
