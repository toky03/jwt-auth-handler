# jwt-auth-handler
Middleware for validating Signature of a JWT Token against jwks endpoint.
## Implement in your own code
``` go
// create the Middleware Handler
jwtHandler, err := jwtauthhandler.CreateJwtHandler("<URL to identity Provider")
// Use the middleware
r.Handle("/products", jwtHandler.AuthMiddleware(ProductsHandler)).Methods("GET")
```

## Tests
`go test -coverprofile=coverage.out`
`go tool cover -html=coverage.out`