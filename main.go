package main

import (
	"context"
	"fmt"
	"net/http"
	"offersapp/models"
	"offersapp/routes"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4"
)

func main() {
	conn, err := connectDB()
	if err != nil {
		return
	}
	router := gin.Default()
	router.Use(dbMiddleware(*conn))

	usersGroup := router.Group("users")
	{
		usersGroup.POST("register", routes.UsersRegister)
		usersGroup.POST("login", routes.UsersLogin)
	}

	itemsGroup := router.Group("items")
	{
		itemsGroup.GET("all", routes.GetItems)
		itemsGroup.POST("create", authMiddleware(), routes.ItemsCreate)
		itemsGroup.GET("sold_by_user", authMiddleware(), routes.ItemsForSaleByCurrentUser)
		itemsGroup.PUT("update", authMiddleware(), routes.ItemsUpdate)

	}

	router.Run()
}

func connectDB() (c *pgx.Conn, err error) {
	conn, err := pgx.Connect(context.Background(), "postgresql://davidevhade:0704502@localhost:5432/offersapp")
	if err != nil {
		fmt.Println("Error connecting to DB")
		fmt.Println(err.Error())
	}
	_ = conn.Ping(context.Background())
	return conn, err
}

func dbMiddleware(conn pgx.Conn) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("db", conn)
		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := c.Request.Header.Get("Authorization")
		split := strings.Split(bearer, "Bearer ")
		if len(split) < 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated. "})
			c.Abort()
			return
		}

		token := split[1]
		isValid, userID := models.IsTokenValid(token)
		if isValid == false {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated. "})
			c.Abort()
		} else {
			// if valid, set user_id to the gin context
			c.Set("user_id", userID)
			c.Next()
		}
	}
}
