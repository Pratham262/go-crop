package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID       int
	Username string
	Password string
	IsAdmin  bool
}

// CropDict maps crop IDs to crop names
var CropDict = map[int]string{
	1: "Rice", 2: "Maize", 3: "Jute", 4: "Cotton", 5: "Coconut", 6: "Papaya",
	7: "Orange", 8: "Apple", 9: "Muskmelon", 10: "Watermelon", 11: "Grapes",
	12: "Mango", 13: "Banana", 14: "Pomegranate", 15: "Lentil", 16: "Blackgram",
	17: "Mungbean", 18: "Mothbeans", 19: "Pigeonpeas", 20: "Kidneybeans",
	21: "Chickpea", 22: "Coffee",
}

// In-memory database for users (in a real app, use a real database)
var users = []User{
	{ID: 1, Username: "admin", Password: hashPassword("admin123"), IsAdmin: true},
	{ID: 2, Username: "user", Password: hashPassword("user123"), IsAdmin: false},
}

// hashPassword hashes the password using bcrypt
func hashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hashedPassword)
}

// For this implementation, we'll simulate the ML model prediction
func predictCrop(features []float64) (int, error) {
	rand.Seed(time.Now().UnixNano())

	sum := 0.0
	for _, v := range features {
		sum += v
	}

	cropID := int(sum) % 22
	if cropID == 0 {
		cropID = 1
	}

	return cropID, nil
}

// imageToBase64 converts an image file to base64 encoding
func imageToBase64(imagePath string) (string, error) {
	imageBytes, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return "", err
	}

	base64Encoding := base64.StdEncoding.EncodeToString(imageBytes)
	return base64Encoding, nil
}

// authMiddleware checks if the user is authenticated
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")

		if userID == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Next()
	}
}

// adminMiddleware checks if the user is an admin
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")

		var isAdmin bool
		for _, user := range users {
			if user.ID == userID {
				isAdmin = user.IsAdmin
				break
			}
		}

		if !isAdmin {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"title": "Access Denied",
				"error": "You don't have permission to access this page",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	// Create the Gin router
	r := gin.Default()

	// Set up sessions
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	// Load HTML templates
	r.LoadHTMLGlob("templates/*")

	// Serve static files
	r.Static("/static", "./static")

	// Create the img directory if it doesn't exist
	if err := os.MkdirAll("static/img", os.ModePerm); err != nil {
		log.Fatal("Failed to create image directory:", err)
	}

	// Create placeholder images for testing
	createPlaceholderImages()

	// Login routes
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "Login",
		})
	})

	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var foundUser *User
		for _, user := range users {
			if user.Username == username {
				foundUser = &user
				break
			}
		}

		if foundUser == nil {
			c.HTML(http.StatusOK, "login.html", gin.H{
				"title": "Login",
				"error": "Invalid username or password",
			})
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password))
		if err != nil {
			c.HTML(http.StatusOK, "login.html", gin.H{
				"title": "Login",
				"error": "Invalid username or password",
			})
			return
		}

		session := sessions.Default(c)
		session.Set("user_id", foundUser.ID)
		session.Save()

		c.Redirect(http.StatusFound, "/")
	})

	// Signup routes
	r.GET("/signup", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signup.html", gin.H{
			"title": "Sign Up",
		})
	})

	r.POST("/signup", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		if password != confirmPassword {
			c.HTML(http.StatusOK, "signup.html", gin.H{
				"title": "Sign Up",
				"error": "Passwords do not match",
			})
			return
		}

		for _, user := range users {
			if user.Username == username {
				c.HTML(http.StatusOK, "signup.html", gin.H{
					"title": "Sign Up",
					"error": "Username already exists",
				})
				return
			}
		}

		newUser := User{
			ID:       len(users) + 1,
			Username: username,
			Password: hashPassword(password),
			IsAdmin:  false,
		}

		users = append(users, newUser)

		session := sessions.Default(c)
		session.Set("user_id", newUser.ID)
		session.Save()

		c.Redirect(http.StatusFound, "/")
	})

	// Logout route
	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.Redirect(http.StatusFound, "/login")
	})

	// Admin dashboard
	r.GET("/admin", authMiddleware(), adminMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", gin.H{
			"title": "Admin Dashboard",
			"users": users,
		})
	})

	// Protected routes
	r.GET("/", authMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "home.html", gin.H{
			"title": "Crop Prediction Application",
		})
	})

	r.GET("/prediction", authMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "prediction.html", gin.H{
			"title": "Crop Prediction Application",
		})
	})

	r.POST("/predict", authMiddleware(), func(c *gin.Context) {
		// Parse form values
		nitrogenStr := c.PostForm("nitrogen")
		phosphorusStr := c.PostForm("phosphorus")
		potassiumStr := c.PostForm("potassium")
		temperatureStr := c.PostForm("temperature")
		humidityStr := c.PostForm("humidity")
		phStr := c.PostForm("ph")
		rainfallStr := c.PostForm("rainfall")

		// Convert strings to float64
		nitrogen, _ := strconv.ParseFloat(nitrogenStr, 64)
		phosphorus, _ := strconv.ParseFloat(phosphorusStr, 64)
		potassium, _ := strconv.ParseFloat(potassiumStr, 64)
		temperature, _ := strconv.ParseFloat(temperatureStr, 64)
		humidity, _ := strconv.ParseFloat(humidityStr, 64)
		ph, _ := strconv.ParseFloat(phStr, 64)
		rainfall, _ := strconv.ParseFloat(rainfallStr, 64)

		// Create features array
		features := []float64{nitrogen, phosphorus, potassium, temperature, humidity, ph, rainfall}

		// Get prediction
		cropID, err := predictCrop(features)
		if err != nil {
			c.HTML(http.StatusOK, "error.html", gin.H{
				"title": "Prediction Error",
				"error": "Failed to make prediction",
			})
			return
		}

		// Get crop name
		cropName, exists := CropDict[cropID]
		if !exists {
			c.HTML(http.StatusOK, "error.html", gin.H{
				"title": "Prediction Error",
				"error": "No suitable crop found for these conditions",
			})
			return
		}

		// Return the prediction result
		c.HTML(http.StatusOK, "result.html", gin.H{
			"title":     "Crop Prediction Result",
			"cropName":  cropName,
			"imagePath": "static\\img\\23.jpg",
		})
	})

	// Start the server
	fmt.Println("Server running at http://localhost:8080")
	r.Run(":8080")
}

// createPlaceholderImages creates placeholder images for testing
func createPlaceholderImages() {
	// Create placeholder images with simple content
	homeImagePath := filepath.Join("static", "img", "3.jpg")
	if _, err := os.Stat(homeImagePath); os.IsNotExist(err) {
		err := ioutil.WriteFile(homeImagePath, []byte("Placeholder for home image"), 0644)
		if err != nil {
			log.Println("Failed to create home image:", err)
		}
	}

	successImagePath := filepath.Join("static", "img", "23.jpg")
	if _, err := os.Stat(successImagePath); os.IsNotExist(err) {
		err := ioutil.WriteFile(successImagePath, []byte("Placeholder for success image"), 0644)
		if err != nil {
			log.Println("Failed to create success image:", err)
		}
	}

	noResultImagePath := filepath.Join("static", "img", "45.jpg")
	if _, err := os.Stat(noResultImagePath); os.IsNotExist(err) {
		err := ioutil.WriteFile(noResultImagePath, []byte("Placeholder for no result image"), 0644)
		if err != nil {
			log.Println("Failed to create no result image:", err)
		}
	}
}
