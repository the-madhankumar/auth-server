package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// Configuration
// In a real app, these would come from environment variables
const (
	AuthServerURL = "https://auth-server-4nmm.onrender.com"            // Replace with your Render URL
	ClientID      = "your-client-id-here"                              // You'll get this after registering the client
	ClientSecret  = "your-client-secret-here"                          // You'll get this after registering the client
	RedirectURI   = "http://localhost:3000/callback"
	AppPort       = ":3000"
)

func main() {
	// Root route - Show "Login" button
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := fmt.Sprintf(`
			<html>
				<body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5;">
					<div style="text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
						<h1 style="margin-bottom: 24px;">My Awesome App</h1>
						<a href="%s/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=read:profile read:email&state=random_state_string" 
						   style="display: inline-block; background: #6366f1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
							Sign in with Auth Server
						</a>
					</div>
				</body>
			</html>
		`, AuthServerURL, ClientID, RedirectURI)
		w.Write([]byte(html))
	})

	// Callback route - Handle code exchange
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code provided", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		tokenURL := fmt.Sprintf("%s/oauth/token", AuthServerURL)
		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		data.Set("code", code)
		data.Set("client_id", ClientID)
		data.Set("client_secret", ClientSecret)
		data.Set("redirect_uri", RedirectURI)

		resp, err := http.PostForm(tokenURL, data)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Error       string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			http.Error(w, "Failed to decode response", http.StatusInternalServerError)
			return
		}

		if tokenResp.Error != "" {
			fmt.Fprintf(w, "Error from auth server: %s", tokenResp.Error)
			return
		}

		// Use token to get user info
		userInfoURL := fmt.Sprintf("%s/oauth/userinfo", AuthServerURL)
		req, _ := http.NewRequest("GET", userInfoURL, nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

		client := &http.Client{}
		userResp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}
		defer userResp.Body.Close()

		var userMap map[string]interface{}
		json.NewDecoder(userResp.Body).Decode(&userMap)

		// Display success page
		fmt.Fprintf(w, `
			<html>
				<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 20px;">
					<h1 style="color: #10b981;">Successfully Logged In! 🎉</h1>
					
					<h3>Your Access Token:</h3>
					<pre style="background: #f1f5f9; padding: 10px; overflow-x: auto;">%s</pre>
					
					<h3>Your User Profile:</h3>
					<pre style="background: #f1f5f9; padding: 10px; border-radius: 6px;">%v</pre>
					
					<p><a href="/">Back to Home</a></p>
				</body>
			</html>
		`, tokenResp.AccessToken, userMap)
	})

	log.Printf("Test client running on http://localhost%s", AppPort)
	log.Fatal(http.ListenAndServe(AppPort, nil))
}
