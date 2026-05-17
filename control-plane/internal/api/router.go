// Package api provides the Gin router setup, CORS middleware, and shared
// HTTP utilities for the Sentinel control-plane REST API.
package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSOptions controls cross-origin behaviour.
type CORSOptions struct {
	// AllowedOrigins is the list of origins permitted to access the API.
	// Use "*" to allow all origins (not recommended for production).
	AllowedOrigins []string

	// AllowedMethods defaults to GET, POST, PUT, PATCH, DELETE, OPTIONS.
	AllowedMethods []string

	// AllowedHeaders defaults to Authorization, Content-Type, X-Requested-With.
	AllowedHeaders []string

	// AllowCredentials sets the Access-Control-Allow-Credentials header.
	AllowCredentials bool

	// MaxAge is the cache duration for preflight responses (seconds).
	MaxAge int
}

// DefaultCORS returns permissive CORS options for local development.
func DefaultCORS() CORSOptions {
	return CORSOptions{
		AllowedOrigins: []string{
			"http://localhost:2222",
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:3005",
			"http://localhost:9501",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin"},
		AllowCredentials: true,
		MaxAge:           86400,
	}
}

// CORSMiddleware returns a gin.HandlerFunc that adds CORS headers to every
// response and handles OPTIONS preflight requests.
func CORSMiddleware(opts CORSOptions) gin.HandlerFunc {
	allowedOriginSet := make(map[string]struct{}, len(opts.AllowedOrigins))
	for _, o := range opts.AllowedOrigins {
		allowedOriginSet[strings.ToLower(o)] = struct{}{}
	}
	allowAll := false
	for _, o := range opts.AllowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
	}
	methods := strings.Join(opts.AllowedMethods, ", ")
	headers := strings.Join(opts.AllowedHeaders, ", ")

	return func(c *gin.Context) {
		origin := strings.ToLower(c.GetHeader("Origin"))

		// Determine the allowed origin for this request.
		allowedOrigin := ""
		if origin == "" {
			// Same-origin request — allow.
			allowedOrigin = origin
		} else if allowAll {
			allowedOrigin = "*"
		} else if _, ok := allowedOriginSet[origin]; ok {
			allowedOrigin = origin
		}

		if allowedOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowedOrigin)
			if opts.AllowCredentials && allowedOrigin != "*" {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
			c.Header("Access-Control-Allow-Methods", methods)
			c.Header("Access-Control-Allow-Headers", headers)
			c.Header("Access-Control-Max-Age", "86400")
			c.Header("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SetupRouter creates a Gin engine with recovery, CORS, and health-check
// middleware.  Route groups are configured by the caller after this returns.
func SetupRouter(corsOpts CORSOptions) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(CORSMiddleware(corsOpts))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return router
}
