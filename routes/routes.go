package routes

import (
	"fmt"

	"github.com/go-auth/internal/auth"
	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/middleware"
	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App, cfg *config.Config) {
	// Main route with authentication check.
	app.Get("/", func(ctx *fiber.Ctx) error {
		cookie := ctx.Cookies("jwt")
		if cookie == "" {
			return ctx.Redirect("/auth")
		}

		return ctx.Redirect("/index.html")
	})

	// Publicly accessible routes.
	app.Get("/auth", auth.Page)
	app.Post("/register", auth.Register)
	app.Post("/login", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: %w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.Login(ctx, cfg) // Call Login with the config.
	})

	// OAuth routes with cfg passed in.
	app.Get("/auth/google", func(ctx *fiber.Ctx) error {
		return auth.HandleGoogleLogin(ctx, cfg)
	})
	app.Get("/auth/google/callback", func(ctx *fiber.Ctx) error {
		return auth.HandleGoogleCallback(ctx, cfg)
	})
	app.Get("/auth/facebook", func(ctx *fiber.Ctx) error {
		return auth.HandleFacebookLogin(ctx, cfg)
	})
	app.Get("/auth/facebook/callback", func(ctx *fiber.Ctx) error {
		return auth.HandleFacebookCallback(ctx, cfg)
	})
	app.Get("/auth/github", func(ctx *fiber.Ctx) error {
		return auth.HandleGitHubLogin(ctx, cfg)
	})
	app.Get("/auth/github/callback", func(ctx *fiber.Ctx) error {
		return auth.HandleGitHubCallback(ctx, cfg)
	})

	// JWT-protected routes with middleware.
	protected := app.Group("/", middleware.AuthMiddleware())
	protected.Get("/users", auth.GetUsers)

	protected.Get("/user/:id", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: %w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.User(ctx, cfg) // Call User with the config
	})
	protected.Put("/user/:id", auth.UpdateUser)
	protected.Delete("/user/:id", auth.DeleteUser)
	protected.Post("/logout", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: %w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.Logout(ctx, cfg)
	})

	// Serve a welcome page for authenticated users.
	protected.Get("/welcome", func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})
}
