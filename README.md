# Go Keycloak Authentication and CRUD Application

This is a Go-based web application that integrates with Keycloak for authentication and provides basic CRUD functionality for managing items.

## Features

- Keycloak Authentication
- Basic CRUD Operations (Create, Read, Update, Delete)
- API Request Handling
- Graceful Shutdown

## Prerequisites

- Go 1.20+
- Keycloak server
- [go-chi](https://github.com/go-chi/chi) for routing
- [coreos/go-oidc](https://github.com/coreos/go-oidc) for OpenID Connect
- [rs/zerolog](https://github.com/rs/zerolog) for logging

## Getting Started

### Keycloak Setup

1. **Create a Realm:**
   - Go to the Keycloak Admin Console.
   - Create a new realm (e.g., `myrealm`).

2. **Create a Client:**
   - Within your realm, create a new client (e.g., `myclient`).
   - Set the `Client ID` to `1234567890` (or any desired value).
   - Set the `Access Type` to `confidential`.
   - Set the `Valid Redirect URIs` to `http://localhost:8081/callback`.

3. **Client Credentials:**
   - Go to the `Credentials` tab of your client.
   - Note down the `Client Secret`.

### Environment Variables

Set the following environment variables based on your Keycloak setup:

- `KEYCLOAK_CLIENT_ID` (e.g., `CLIENTID`)
- `KEYCLOAK_CLIENT_SECRET` (e.g., `CLIENTSECRET`)
- `KEYCLOAK_REDIRECT_URL` (e.g., `http://localhost:8081/callback`)
- `KEYCLOAK_LOGOUT_REDIRECT_URL` (e.g., `http://localhost:8081/login`)
- `KEYCLOAK_ISSUER_URL` (e.g., `http://localhost:8080/realms/myrealm`)

### Running the Application

1. **Clone the Repository:**

   ```sh
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies:**

   ```sh
   go mod tidy
   ```

3. **Run the Application:**

   ```sh
   go run main.go
   ```

   The server will start on `http://localhost:8081`.

## API Endpoints

- **GET** `/login` - Main login page.
- **GET** `/key-cloak-login` - Redirects to Keycloak for authentication.
- **GET** `/callback` - Handles Keycloak callback after authentication.
- **GET** `/logout` - Logs out the user and redirects to login page.
- **GET** `/api` - Handles API requests.

### CRUD Operations

- **GET** `/` - List all items.
- **GET** `/create` - Display form to create a new item.
- **POST** `/create` - Create a new item.
- **GET** `/update/{id}` - Display form to update an item.
- **POST** `/update/{id}` - Update an item.
- **GET** `/delete/{id}` - Display form to delete an item.
- **POST** `/delete/{id}` - Delete an item.

## Middleware

- `tokenValidationMiddleware` - Validates the presence of `id_token` in cookies for protected routes.

## Graceful Shutdown

The application supports graceful shutdown, allowing ongoing requests to complete before the server exits.
