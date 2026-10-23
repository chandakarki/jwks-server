# JWKS Server – Project 2

**CSCE 3550 – Foundations of Cybersecurity**  
University of North Texas

## Project Overview

This project extends a basic JSON Web Key Set (JWKS) server by adding SQLite database storage for RSA private keys.

The server is built using Python and Flask. It generates RSA key pairs, stores private keys in a SQLite database, issues signed JSON Web Tokens (JWTs), and provides public keys through a JWKS endpoint.

The project also demonstrates how expired keys are handled and how parameterized SQL queries help protect against SQL injection attacks.

## Technologies Used

- Python
- Flask
- SQLite
- PyJWT
- cryptography
- pytest
- pytest-cov
- Git and GitHub

## Database Implementation

The server uses a SQLite database named `totally_not_my_privateKeys.db`.

The database contains a table named `keys` with the following columns:

| Column | Description |
|---|---|
| kid | Automatically generated primary key |
| key | RSA private key stored in PEM format |
| exp | Key expiration time stored as a Unix timestamp |

The database is initialized when the application starts.

Private keys are stored in the database rather than being maintained only in memory.

The database file is excluded from GitHub using `.gitignore` to avoid publishing private keys.

## API Endpoints

### GET /.well-known/jwks.json

Returns the public RSA keys that have not expired.

Expired keys are excluded from the JWKS response.

### POST /auth

Generates a JWT signed using a valid RSA private key retrieved from SQLite.

### POST /auth?expired

Generates a JWT using an expired RSA private key for testing expiration behavior.

## SQL Injection Protection

The application uses parameterized SQL queries when interacting with the SQLite database.

For example:

```python
cursor = conn.execute(
    "INSERT INTO keys (key, exp) VALUES (?, ?)",
    (pem, int(expiry.timestamp()))
)
```

Using placeholders helps prevent SQL injection by separating SQL instructions from parameter values.

## Running the Project

Install the required Python packages:

```bash
pip install flask pyjwt cryptography pytest pytest-cov
```

Start the Flask server:

```bash
python -m app.main
```

The server runs on port 8080.

## Testing

Run the automated tests with coverage:

```bash
python -m pytest --cov=app --cov-report=term-missing
```

Latest local test results:

- **21 tests passed**
- **81% code coverage**
- **98.57% Gradebot score**

The tests cover database operations, key generation, JWT authentication, expired keys, and JWKS endpoint behavior.

## Project Structure

```text
jwks-server/
├── app/
│   └── main.py
├── tests/
│   └── test_main.py
├── .gitignore
├── README.md
├── coverage-screenshot.png
└── gradebot-screenshot.png
```

The SQLite database and Python virtual environment are excluded from version control.

## Security Notes

- RSA private keys are stored in SQLite.
- Only public keys are exposed through the JWKS endpoint.
- Expired keys are excluded from the JWKS response.
- Parameterized queries help prevent SQL injection.
- Private-key database files are not committed to GitHub.
