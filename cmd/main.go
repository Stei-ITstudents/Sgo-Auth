// main.go

package main

import (
	"log"

	"github.com/go-auth/internal/config" // Import the config package
	"github.com/go-auth/internal/database"
	"github.com/go-auth/internal/middleware"
	"github.com/go-auth/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
	"github.com/sirupsen/logrus"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Now GetDB will handle connection and migration, no need to call AutoMigrate again
	database.GetDB() // This will connect and migrate

	// Removed the redundant migration line
	// if err := dbInstance.DB.AutoMigrate(&models.User{}); err != nil {
	//	logrus.Fatalf("Failed to migrate database: %v", err)
	// }

	engine := html.New("./web/html", ".html")

	// Create a new Fiber instance with template engine
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Serve static files from the "web" directory
	app.Static("/", "./web/html")
	app.Static("/ico", "./web/img/ico")
	app.Static("/css", "./web/css")
	app.Static("/js", "./web/js")
	app.Static("/img", "./web/img")

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:8000",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin,Content-Type,Accept",
	}))

	// Inject the configuration into the context
	app.Use(middleware.ConfigMiddleware(cfg))

	// // Use the AuthMiddleware which retrieves the config from context
	// app.Use(middleware.AuthMiddleware())

	// Setup routes
	routes.Setup(app, cfg)

	// Start the server
	if err := app.Listen(":8000"); err != nil {
		logrus.Errorf("Failed to start server: %v", err)
	}
}
