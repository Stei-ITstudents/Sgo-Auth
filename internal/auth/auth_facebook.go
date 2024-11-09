package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/logrus"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var ErrCodeNotFound = errors.New("failed to find code in callback request")

func HandleFacebookLogout(ctx *fiber.Ctx, _ *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleFacebookLogout s ---")

	accessToken := ctx.Locals("access_token")
	accessTokenStr, ok := accessToken.(string)

	if !ok {
		logrus.Error("Invalid access token type")

		return fmt.Errorf("failed to send response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid access token type"}))
	}

	revokeTokenURL := "https://graph.facebook.com/me/permissions?access_token=" + accessTokenStr
	logrus.Infof("Revoking Facebook token at URL: ➽%v", revokeTokenURL)

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodDelete, revokeTokenURL, nil)

	if err != nil {
		logrus.Error("Failed to create revoke request: ", err)

		return fmt.Errorf("failed to create revoke request: ➽%w",
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

	logrus.Info("Facebook token revoked successfully")

	return nil
}

// Redirects user to Facebook login page.
func HandleFacebookLogin(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleFacebookLogin s ---")

	facebookOauthConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.FacebookClientID,
		ClientSecret: cfg.OAuth.FacebookClientSecret,
		RedirectURL:  "http://localhost:8000/auth/facebook/callback",
		Scopes:       []string{"email"},
		Endpoint:     facebook.Endpoint,
	}

	url := facebookOauthConfig.AuthCodeURL("state")
	if err := ctx.Redirect(url); err != nil {
		return fmt.Errorf("failed to redirect to Facebook login: ➽%w", err)
	}

	return nil
}

// Handles Facebook OAuth callback and fetches user info.
func HandleFacebookCallback(ctx *fiber.Ctx, cfg *config.Config) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleFacebookCallback s ---")

	facebookOauthConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.FacebookClientID,
		ClientSecret: cfg.OAuth.FacebookClientSecret,
		RedirectURL:  "http://localhost:8000/auth/facebook/callback",
		Scopes:       []string{"email"},
		Endpoint:     facebook.Endpoint,
	}

	code := ctx.Query("code")
	if code == "" {
		return fmt.Errorf("failed to send response: ➽%w",
			ctx.Status(fiber.StatusBadRequest).SendString("Code not found in callback request"))
	}

	logrus.Infof("Received Facebook code: ➽%v", code)

	token, err := facebookOauthConfig.Exchange(ctx.Context(), code)
	if err != nil {
		return fmt.Errorf("failed to send response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).SendString("Failed to exchange token: "+err.Error()))
	}

	logrus.Infof("Received Facebook token: ➽%+v", token)

	client := facebookOauthConfig.Client(ctx.Context(), token)
	req, err := http.NewRequestWithContext(
		ctx.Context(),
		http.MethodGet,
		"https://graph.facebook.com/me?fields=id,name,email",
		nil,
	)

	logrus.Infof("Request: ➽%+v", req)
	logrus.Infof("Client: ➽%+v", client)

	if err != nil {
		return fmt.Errorf("failed to create request: ➽%w", err)
	}

	resp, err := client.Do(req)
	logrus.Infof("Response: ➽%+v", resp)

	if err != nil {
		return fmt.Errorf("failed to get user info: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).SendString("Failed to get user info: "+err.Error()))
	}

	defer resp.Body.Close()

	userInfo, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to send response: ➽%w",
			ctx.Status(fiber.StatusInternalServerError).SendString("Failed to read user info: "+err.Error()))
	}

	logrus.Infof("Received user info: ➽%s", userInfo)

	if err := ctx.SendString("Facebook login successful: " + string(userInfo)); err != nil {
		return fmt.Errorf("failed to send response: ➽%w", err)
	}

	if err := ctx.Redirect("/index.html"); err != nil {
		return fmt.Errorf("failed to redirect: ➽%w", err)
	}

	return nil
}
