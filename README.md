# a13core

`a13core` is a collection of Go libraries developed by a13labs to provide reusable components for various Go projects. These libraries include functionality for authentication, logging, and more.

## Features

- **Authentication**: 
  - Support for multiple authentication providers (file-based, in-memory, and null).
  - JWT-based token generation and verification.
  - Role-based access control.

- **Logging**:
  - Configurable logging with support for file-based logging.
  - Log levels: Info, Warn, Error, Debug.

## Project Structure

### Key Directories

- **`auth/`**: Contains authentication-related logic, including token management and provider implementations.
- **`logger/`**: Provides logging utilities using `logrus`.

## Getting Started

### Prerequisites

- Go 1.23.4 or later.

### Installation

Clone the repository:

```bash
git clone https://github.com/a13labs/a13core.git
cd a13core
```

Usage

### Authentication

1. Initialize the authentication system:

```go
import (
    "encoding/json"
    "github.com/a13labs/a13core/auth"
)

func main() {
    config := `{
        "provider": "file",
        "secret_key": "your-secret-key",
        "expiration_time": 24,
        "settings": {
            "file_path": "./users.json"
        }
    }`

    err := auth.InitializeAuth([]byte(config))
    if err != nil {
        panic(err)
    }
}
```
2. Generate token
```go
token, err := auth.CreateToken("username", "password")
if err != nil {
    fmt.Println("Error:", err)
} else {
    fmt.Println("Token:", token)
}
```
3. Verify token
```go
isValid := auth.VerifyToken(token)
fmt.Println("Token valid:", isValid)
```

### Logging
1. Initialize the logger
```go
import "github.com/a13labs/a13core/logger"

func main() {
    logger.Init("app.log")
    logger.Info("Application started")
}
```
2. Log messages
```go
logger.Info("This is an info message")
logger.Warn("This is a warning")
logger.Error("This is an error")
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue to discuss any changes or improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Go community for providing the tools and resources to build this project.
- Special mention to the developers of libraries and tools used in this project.
