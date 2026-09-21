# JWKS Server

A Python/Flask cybersecurity project implementing a JSON Web Key Set (JWKS) server and JWT-based authentication.
Developed as part of CSCE 3550 – Foundations of Cybersecurity at the University of North Texas.
## Overview

This project demonstrates how a server can generate RSA key pairs, issue signed JSON Web Tokens (JWTs), and expose active public keys through a JWKS endpoint.

The server maintains both a valid key and an expired key to demonstrate key expiration and filtering.

## Technologies

- Python
- Flask
- PyJWT
- cryptography
- pytest
- RSA
- RS256
- Git/GitHub

## Endpoints

### JWKS

`GET /.well-known/jwks.json`

Returns the currently active public key in JWK format.

Expired keys are excluded from the JWKS response.

### Authentication

`POST /auth`

Generates a JWT signed with the valid RSA private key.

`POST /auth?expired`

Generates a JWT using the expired key for testing expiration behavior.

## Testing

The project includes automated pytest tests covering:

- JWKS endpoint responses
- Valid key inclusion
- Expired key exclusion
- JWK structure and required fields
- JWT generation
- JWT key IDs (`kid`)
- Expired JWT behavior
- HTTP method restrictions

## Project Structure

```text
jwks-server/
├── app/
│   └── main.py
├── tests/
│   └── test_main.py
├── coverage-screenshot.png
└── gradebot-screenshot.png
