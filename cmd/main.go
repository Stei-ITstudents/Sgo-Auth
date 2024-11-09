// main.go

package main

import (
	"log"

	"github.com/go-auth/internal/auth"   // Import the config package
	"github.com/go-auth/internal/config" // Import the config package
	"github.com/go-auth/internal/database"
	"github.com/go-auth/internal/middleware"
	"github.com/go-auth/logrus"
	"github.com/go-auth/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
)

func main() { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- main ---")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: ➽%v", err)
	}

	engine := html.New("./web/html", ".html")

	// Create a new Fiber instance with template engine
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Inject the configuration into the context
	app.Use(middleware.ConfigMiddleware(cfg))

	// Create the admin user using loaded config values
	if err := auth.CreateAdminUser(database.GetDB(), cfg.AdminUsername, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		logrus.Errorf("Error creating admin user: ➽%v", err)
	}

	// Serve static files from the "web" directory, except for index.html
	app.Static("/ico", "./web/img/ico")
	app.Static("/css", "./web/css")
	app.Static("/js", "./web/js")
	app.Static("/img", "./web/img")

	// Setup routes
	routes.Setup(app, cfg)

	app.Get("/index.html", middleware.AuthMiddleware(), func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:8000",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin,Content-Type,Accept",
	}))

	// Start the server
	if err := app.Listen(":8000"); err != nil {
		logrus.Errorf("Failed to start server: ➽%v", err)
	}
}
