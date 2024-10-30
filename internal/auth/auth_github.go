package auth

import (
	"fmt"
	"io"
	"net/http"

	"github.com/go-auth/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func HandleGithubLogout(ctx *fiber.Ctx, cfg *config.Config) error {
	accessToken := ctx.Locals("access_token")
	accessTokenStr, ok := accessToken.(string)

	if !ok {
		logrus.Error("Invalid access token type")

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid access token type"}))
	}

	revokeTokenURL := "https://api.github.com/applications/" + cfg.OAuth.GithubClientID + "/tokens/" + accessTokenStr
	logrus.Infof("Revoking GitHub token at URL: %v", revokeTokenURL)

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodDelete, revokeTokenURL, nil)
	if err != nil {
		logrus.Error("Failed to create revoke request: ", err)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create revoke request"}))
	}

	req.SetBasicAuth(cfg.OAuth.GithubClientID, cfg.OAuth.GithubClientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		logrus.Error("Failed to revoke token: ", err)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		logrus.Errorf("Failed to revoke token, status code: %v", resp.StatusCode)

		return fmt.Errorf("failed to send JSON response: %w",
			ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to revoke token"}))
	}

	logrus.Info("GitHub token revoked successfully")

	return nil
}

func NewGithubOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.OAuth.GithubClientID,
		ClientSecret: cfg.OAuth.GithubClientSecret,
		RedirectURL:  "http://localhost:8000/auth/github/callback",
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
}

func HandleGitHubLogin(ctx *fiber.Ctx, cfg *config.Config) error {
	githubOauthConfig := NewGithubOAuthConfig(cfg)
	url := githubOauthConfig.AuthCodeURL("state")

	if err := ctx.Redirect(url); err != nil {
		return fmt.Errorf("failed to redirect to GitHub login: %w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to redirect to GitHub login: "+err.Error(),
		))
	}

	logrus.Info("Redirected to GitHub login")

	return nil
}

func HandleGitHubCallback(ctx *fiber.Ctx, cfg *config.Config) error {
	githubOauthConfig := NewGithubOAuthConfig(cfg)
	code := ctx.Query("code")

	if code == "" {
		return fmt.Errorf("failed to find code in callback request: %w", ctx.Status(fiber.StatusBadRequest).SendString(
			"Code not found in callback request",
		))
	}

	token, err := githubOauthConfig.Exchange(ctx.Context(), code)
	if err != nil {
		return fmt.Errorf("failed to exchange token: %w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to exchange token: "+err.Error(),
		))
	}

	client := githubOauthConfig.Client(ctx.Context(), token)
	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodGet, "https://api.github.com/user", nil)

	if err != nil {
		return fmt.Errorf("failed to create request: %w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to create request: "+err.Error(),
		))
	}

	resp, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("failed to get user info: %w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to get user info: "+err.Error(),
		))
	}

	defer resp.Body.Close()

	userInfo, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read user info: %w", ctx.Status(fiber.StatusInternalServerError).SendString(
			"Failed to read user info: "+err.Error(),
		))
	}

	if err := ctx.SendString("GitHub login successful: " + string(userInfo)); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	if err := ctx.Redirect("/index.html"); err != nil {
		return fmt.Errorf("failed to redirect: %w", err)
	}

	logrus.Info("GitHub login successful")

	return nil
}
