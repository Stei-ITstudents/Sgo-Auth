package routes

import (
	"fmt"

	"github.com/go-auth/internal/auth"
	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/middleware"
	"github.com/go-auth/logrus"
	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App, cfg *config.Config) {
	logrus.Debugf("--- Routes Setup ---")

	// *Index route.
	app.Get("/", func(ctx *fiber.Ctx) error {
		cookie := ctx.Cookies("jwt")
		if cookie == "" {
			return ctx.Redirect("/auth")
		}

		return ctx.Redirect("/index.html")
	})

	// *Auth route.
	app.Get("/auth", auth.Page)

	// *Register route.
	app.Post("/register", auth.Register)

	// *Login route with cfg passed in.
	app.Post("/login", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: 🟢%w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.Login(ctx, cfg) // Call Login with the config.
	})

	// *OAuth routes with cfg passed in.
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

	// *Create user route.
	app.Post("/user", auth.Register)

	// *JWT-protect routes with middleware.
	protected := app.Group("/", middleware.AuthMiddleware())

	// *Protect direct access to index.html
	protected.Get("/index.html", middleware.AuthMiddleware(), func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})

	// *Protect access to protected-index.html
	protected.Get("/protected-index", middleware.AuthMiddleware(), func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})

	// *Get all users route.
	protected.Get("/users", auth.GetUsers)

	// *Get User route.
	// protected.Get("/user/:email", auth.GetUser).
	protected.Get("/user", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config) // Retrieve the config from the context.
		if !ok {
			return fmt.Errorf("failed to retrieve config: 🟢%w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.User(ctx, cfg) // Call User with the config
	})

	// *Update user route.
	protected.Put("/user", auth.UpdateUser)

	// *Delete user route.
	protected.Delete("/user", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: 🟢%w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.DeleteUser(ctx, cfg)
	})

	// *Logout route.
	protected.Post("/logout", func(ctx *fiber.Ctx) error {
		cfg, ok := ctx.Locals("config").(*config.Config)
		if !ok {
			return fmt.Errorf("failed to retrieve config: 🟢%w",
				ctx.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve config"))
		}

		return auth.Logout(ctx, cfg)
	})

	// *Serve a welcome page for authenticated users.
	protected.Get("/welcome", func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})
}
