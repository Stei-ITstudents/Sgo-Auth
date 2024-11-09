package auth

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/logrus"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func HandleGoogleLogout(ctx *fiber.Ctx, _ *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleGoogleLogout s ---")

	// Retrieve the access token from the context
	accessToken := ctx.Locals("access_token")
	accessTokenStr, ok := accessToken.(string)
	logrus.Info("Access token: ", accessTokenStr)

	if !ok {
		logrus.Error("Invalid access token type")

		return fmt.Errorf("failed to send error response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid access token type"}))
	}

	// Revoke the Google OAuth token
	revokeTokenURL := "https://oauth2.googleapis.com/revoke?token=" + accessTokenStr
	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodPost, revokeTokenURL, nil)

	if err != nil {
		logrus.Error("Failed to create revoke request: ", err)

		return fmt.Errorf("failed to send error response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create revoke request"}))
	}

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		logrus.Error("Failed to revoke token: ", err)

		return fmt.Errorf("failed to revoke token: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("Failed to revoke token, status code: ➽%v", resp.StatusCode)

		return fmt.Errorf("failed to revoke token: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
	}

	logrus.Info("Google token revoked successfully")

	// Clear the JWT cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})
	logrus.Info("JWT cookie cleared")

	// Clear the session cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "session",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})
	logrus.Info("Session cookie cleared")

	return nil
}

func HandleGoogleLogin(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleGoogleLogin s ---")

	googleOauthConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.GoogleClientID,
		ClientSecret: cfg.OAuth.GoogleClientSecret,
		RedirectURL:  "http://localhost:8000/auth/google/callback", // Ensure this matches the JSON config
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	url := googleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	if err := ctx.Redirect(url); err != nil {
		return fmt.Errorf("failed to redirect to Google login: ➽%w", err)
	}

	return nil
}

func HandleGoogleCallback(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleGoogleCallback s ---")

	googleOauthConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.GoogleClientID,
		ClientSecret: cfg.OAuth.GoogleClientSecret,
		RedirectURL:  "http://localhost:8000/auth/google/callback", // Ensure this matches the JSON config
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	code := ctx.Query("code")
	token, err := googleOauthConfig.Exchange(ctx.Context(), code)

	logrus.Infof("Received code: %s", code)
	logrus.Infof("Received token: %+v", token)

	if err != nil {
		if sendErr := ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to exchange token"); sendErr != nil {
			return fmt.Errorf("failed to send error response: ➽%w", sendErr)
		}

		return fmt.Errorf("failed to exchange token: ➽%w", err)
	}

	client := googleOauthConfig.Client(ctx.Context(), token)
	req, err := http.NewRequestWithContext(
		ctx.Context(),
		http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo",
		nil,
	)

	logrus.Infof("Request: %+v", req)
	logrus.Infof("Client: %+v", client)

	if err != nil {
		return fmt.Errorf(
			"failed to create request: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).SendString("Failed to create request"),
		)
	}

	resp, err := client.Do(req)
	logrus.Infof("Response: %+v", resp)

	if err != nil {
		return fmt.Errorf("failed to get user info: ➽%w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to get user info",
		))
	}

	defer resp.Body.Close()

	userInfo, err := io.ReadAll(resp.Body)
	logrus.Infof("User info: %s", userInfo)

	if err != nil {
		return fmt.Errorf(
			"failed to read user info: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).SendString("Failed to read user info"),
		)
	}

	if err := ctx.SendString("Google login successful: " + string(userInfo)); err != nil {
		return fmt.Errorf("failed to send response: ➽%w", err)
	}

	if err := ctx.Redirect("/index.html"); err != nil {
		return fmt.Errorf("failed to redirect: ➽%w", err)
	}

	return nil
}
