package auth

import (
	"fmt"
	"strings"

	"github.com/go-auth/internal/config"
	"github.com/go-auth/logrus"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// Page handles the rendering of the authentication page.
func Page(ctx *fiber.Ctx) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- Page s ---")

	if err := ctx.SendFile("./web/html/auth.html"); err != nil {
		return fmt.Errorf("failed to send auth page: ➽%w", err)
	}

	return nil
}

func parseRequestBody(ctx *fiber.Ctx) (map[string]string, error) { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- parseRequestBody s ---")

	var data map[string]string
	if err := ctx.BodyParser(&data); err != nil {
		return nil, fmt.Errorf("error parsing request body: ➽%w", err)
	}

	return data, nil
}

// HandleErr sends a JSON error response with a status code, message, and optional error details.
func HandleErr(ctx *fiber.Ctx, status int, message string, err error) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- HandleErr s ---")

	response := fiber.Map{
		"error":   message,
		"status":  status,
		"details": nil,
	}

	if err != nil {
		logrus.Error(err)
		response["details"] = err.Error()
	}

	if jsonErr := ctx.Status(status).JSON(response); jsonErr != nil {
		logrus.Error("Failed to send JSON response: ", jsonErr)

		return fmt.Errorf("failed to send JSON response: ➽%w", jsonErr)
	}

	return nil
}

// logrus.Infof(" Claims: ➽%+v", claims).
func GetHeader(ctx *fiber.Ctx, logMessage string) map[string]string { // $➮🗝️ᐅ➽⊛
	Header := make(map[string]string)
	ReqHeader := &ctx.Request().Header
	ReqHeader.VisitAll(func(key, value []byte) {
		Header[string(key)] = string(value)
	})

	// return Header
	logrus.WithFields(logrus.ToFields(Header)).Infof("⊛➮ " + logMessage + " Header")
	// Return the headers
	return Header
}

func GetCookies(ctx *fiber.Ctx, logMessage string) map[string]string { // $➮🗝️ᐅ➽⊛
	cookies := make(map[string]string)

	for _, cookie := range strings.Split(string(ctx.Request().Header.Peek("Cookie")), "; ") {
		parts := strings.SplitN(cookie, "=", Split2)
		if len(parts) == Split2 {
			cookies[parts[0]] = parts[1]
		}
	}

	logrus.WithFields(logrus.ToFields(cookies)).Infof("⊛➮ " + logMessage + " Cookies")

	return cookies
}

// ParseAndValidateJWT parses and validates the JWT token from the Authorization header.
func ParseJWT(ctx *fiber.Ctx, cfg *config.Config, logMessage string) error { // $➮🗝️ᐅ➽⊛
	logrus.Debugf("--- ParseJWT s ---")

	// *Retrieve the JWT token.
	JWT := ctx.Cookies("jwt")

	// *Assert JWT token.
	if JWT == "" {
		logrus.Errorf("JWT token not found in cookie")

		return HandleErr(ctx, fiber.StatusUnauthorized, "JWT token not found", nil)
	}

	// *Parse the JWT token.
	parsedToken, err := jwt.ParseWithClaims(JWT, &CustomClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return cfg.JWTSecretKey, nil
	})
	if err != nil {
		logrus.Errorf("Error parsing JWT: ➽%v", err)

		return HandleErr(ctx, fiber.StatusUnauthorized, "Invalid token", err)
	}
	// *Check if the token is valid and extract the claims.
	if claims, ok := parsedToken.Claims.(*CustomClaims); ok && parsedToken.Valid {
		// Raw
		logrus.Infof("⊛➮ "+logMessage+" Parsed JWT: ➽%s", parsedToken.Raw)
		// Header
		logrus.Infof("➮  Algorithm: ➽%v", parsedToken.Header["alg"]) // HMAC SHA256.
		logrus.Infof("➮       Type: ➽%v", parsedToken.Header["typ"])
		// Payload
		logrus.Infof("➮     Issuer: ➽%v", claims.Issuer)
		logrus.Infof("➮    Purpose: ➽%v", claims.Purpose)
		logrus.Infof("➮   Audience: ➽%v", claims.Audience)
		logrus.Infof("➮ authMethod: ➽%v", claims.AuthMethod)
		logrus.Infof("➮    Subject: ➽%v", claims.Subject)
		// logrus.Infof("➮  Issued At: ➽%v", claims.IssuedAt)
		// Signatures
		// logrus.Infof("➮  Signature: ➽%s", parsedToken.Signature)
		// decodedSignature, err := base64.RawURLEncoding.DecodeString(parsedToken.Signature)

		// if err != nil {
		// 	logrus.Errorf("Error decoding signature: ➽%v", err)

		// 	return fmt.Errorf("error decoding signature: %w", err)
		// }

		// logrus.Infof("➮ StrDecSign: ➽%x", string(decodedSignature))
		logrus.Infof("➮ Expiration: ➽%v", claims.ExpiresAt)
	} else {
		logrus.Errorf("Invalid token claims or parsing failed")

		return HandleErr(ctx, fiber.StatusUnauthorized, "Invalid token claims", err)
	}

	return nil
}
