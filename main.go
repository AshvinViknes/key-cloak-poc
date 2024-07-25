package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

var (
	clientID          = "clientID"                       	// obtained from Keycloak Admin Console
	clientSecret      = "secretKey" 			// obtained from Keycloak Admin Console
	redirectURL       = "http://localhost:8081/callback"    // your application’s callback URL
	logoutRedirectURL = "http://localhost:8081/login"
	issuerURL         = "http://localhost:8080/realms/myrealm" // Keycloak realm configuration URL
)

var (
	oidcProvider *oidc.Provider
	oauth2Config oauth2.Config
)

func initOIDCProvider(ctx context.Context) {
	log.Info().Msgf("Fetching Keycloak provider configuration from: %s", issuerURL)

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get provider")
	}
	oidcProvider = provider
	log.Info().Msg("Successfully fetched provider configuration")

	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	ctx := context.Background()

	// Initialize OIDC provider
	initOIDCProvider(ctx)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/login", handleMain)
	r.Get("/key-cloak-login", handleLogin)
	r.Get("/callback", handleCallback)
	r.Get("/logout", handleLogout)  // Added logout route
	r.Get("/api", handleAPIRequest) // Added route for API request

	// CRUD routes
	r.With(tokenValidationMiddleware).Get("/", listItems)
	r.With(tokenValidationMiddleware).Get("/create", createItemForm)
	r.With(tokenValidationMiddleware).Post("/create", createItem)
	r.With(tokenValidationMiddleware).Get("/update/{id}", updateItemForm)
	r.With(tokenValidationMiddleware).Post("/update/{id}", updateItem)
	r.With(tokenValidationMiddleware).Get("/delete/{id}", deleteItemForm)
	r.With(tokenValidationMiddleware).Post("/delete/{id}", deleteItem)

	server := &http.Server{
		Addr:         ":8081",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server ListenAndServe")
		}
	}()
	log.Info().Msg("Server starting on http://localhost:8081")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctxShutDown); err != nil {
		log.Fatal().Err(err).Msg("Server Shutdown Failed")
	}
	log.Info().Msg("Server exited properly")
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	log.Info().Msgf("Redirecting to: %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Error().Msg("No id_token field in oauth2 token")
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	idToken, err := oidcProvider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify ID Token")
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		log.Error().Err(err).Msg("Failed to parse claims")
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	// Store the token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "id_token",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  token.Expiry,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear cookies by setting them with an expired date
	clearCookie := http.Cookie{
		Name:     "id_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, &clearCookie)
	// Construct the Keycloak logout URL
	logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?client_id=%s&post_logout_redirect_uri=%s", issuerURL, clientID, logoutRedirectURL)
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("id_token")
	if err != nil {
		log.Error().Err(err).Msg("No id_token cookie found")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	req, err := http.NewRequest("GET", "http://example.com/api/protected", nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create API request")
		http.Error(w, "Failed to create API request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie.Value))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to access protected API")
		http.Error(w, "Failed to access protected API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Error().Err(err).Msg("Failed to decode API response")
		http.Error(w, "Failed to decode API response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func tokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("id_token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/key-cloak-login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Item struct {
	ID   int
	Name string
}

var items = []Item{}
var nextID = 1

func listItems(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>CRUD Application</title>
		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
	</head>
	<body>
		<div class="container">
			<div class="mt-5">
				<h1>Item List</h1>
				<div class="d-grid float-right">
					<a href="/create" class="btn btn-primary mb-3">Add New Item</a>
                    <a href="/logout" class="btn btn-danger mb-3">Logout</a>
				</div>
				<table class="table table-bordered">
					<thead>
						<tr>
							<th>ID</th>
							<th>Name</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{{ range .Items }}
						<tr>
							<td>{{ .ID }}</td>
							<td>{{ .Name }}</td>
							<td>
								<a href="/update/{{ .ID }}" class="btn btn-warning">Update</a>
								<a href="/delete/{{ .ID }}" class="btn btn-danger">Delete</a>
							</td>
						</tr>
						{{ end }}
					</tbody>
				</table>
			</div>
		</div>
	</body>
	</html>
	`))

	data := struct {
		Items []Item
	}{
		Items: items,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Error().Err(err).Msg("Failed to render template")
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func createItemForm(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>CRUD Application</title>
		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
	</head>
	<body>
		<div class="container">
			<div class="mt-5">
				<h1>Add New Item</h1>
				<form action="/create" method="POST">
					<div class="form-group">
						<label for="name">Name</label>
						<input type="text" class="form-control" id="name" name="name" required>
					</div>
					<button type="submit" class="btn btn-success">Add</button>
					<a href="/" class="btn btn-secondary">Cancel</a>
				</form>
			</div>
		</div>
	</body>
	</html>
	`))

	if err := tmpl.Execute(w, nil); err != nil {
		log.Error().Err(err).Msg("Failed to render template")
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func createItem(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	items = append(items, Item{ID: nextID, Name: name})
	nextID++
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func updateItemForm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var item *Item
	for i := range items {
		if items[i].ID == id {
			item = &items[i]
			break
		}
	}

	if item == nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	tmpl := template.Must(template.New("").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>CRUD Application</title>
		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
	</head>
	<body>
		<div class="container">
			<div class="mt-5">
				<h1>Update Item</h1>
				<form action="/update/{{ .Item.ID }}" method="POST">
					<div class="form-group">
						<label for="name">Name</label>
						<input type="text" class="form-control" id="name" name="name" value="{{ .Item.Name }}" required>
					</div>
					<button type="submit" class="btn btn-success">Update</button>
					<a href="/" class="btn btn-secondary">Cancel</a>
				</form>
			</div>
		</div>
	</body>
	</html>
	`))

	data := struct {
		Item *Item
	}{
		Item: item,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Error().Err(err).Msg("Failed to render template")
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func updateItem(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	for i := range items {
		if items[i].ID == id {
			items[i].Name = name
			break
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteItemForm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var item *Item
	for i := range items {
		if items[i].ID == id {
			item = &items[i]
			break
		}
	}

	if item == nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	tmpl := template.Must(template.New("").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>CRUD Application</title>
		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
	</head>
	<body>
		<div class="container">
			<div class="mt-5">
				<h1>Delete Item</h1>
				<p>Are you sure you want to delete this item?</p>
				<form action="/delete/{{ .Item.ID }}" method="POST">
					<button type="submit" class="btn btn-danger">Delete</button>
					<a href="/" class="btn btn-secondary">Cancel</a>
				</form>
			</div>
		</div>
	</body>
	</html>
	`))

	data := struct {
		Item *Item
	}{
		Item: item,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Error().Err(err).Msg("Failed to render template")
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func deleteItem(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	for i := range items {
		if items[i].ID == id {
			items = append(items[:i], items[i+1:]...)
			break
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
