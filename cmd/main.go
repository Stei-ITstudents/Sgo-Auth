// main.go

package main

import (
	"log"

	"github.com/go-auth/internal/auth"
	"github.com/go-auth/internal/config"
	"github.com/go-auth/internal/database"
	"github.com/go-auth/internal/middleware"
	"github.com/go-auth/logrus"
	"github.com/go-auth/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
)

func main() {
	logrus.Debugf("--- main ---")

	// *Load configuration.
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: 🟢%v", err)
	}

	// *Set .html template.
	engine := html.New("./web/html", ".html")

	// *Create a new Fiber instance.
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// *Inject the configuration into the context.
	app.Use(middleware.ConfigMiddleware(cfg))

	// *Create the admin user using loaded config values.
	if err := auth.CreateAdminUser(database.GetDB(), cfg.AdminUsername, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		logrus.Errorf("Error creating admin user: 🟢%v", err)
	}

	// *Serve static files.
	app.Static("/ico", "./web/img/ico")
	app.Static("/css", "./web/css")
	app.Static("/js", "./web/js")
	app.Static("/img", "./web/img")

	routes.Setup(app, cfg)

	// *Index route.
	app.Get("/index.html", middleware.AuthMiddleware(), func(ctx *fiber.Ctx) error {
		return ctx.SendFile("./web/html/index.html")
	})

	// *CORS middleware.
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:8000",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin,Content-Type,Accept",
	}))

	// *Start the server.
	if err := app.Listen(":8000"); err != nil {
		logrus.Errorf("Failed to start server: 🟢%v", err)
	}
}
