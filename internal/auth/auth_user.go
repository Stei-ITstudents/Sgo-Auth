package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

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
