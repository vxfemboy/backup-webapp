# A Simple Backup SystemWebApp

This is a simple web-based application designed to automate the process of creating and managing backups for specified directories. It provides a user-friendly interface for initiating backups, monitoring progress, and downloading backup files. The application is built using Go and the Gin web framework, and it supports both HTTP and HTTPS.

## Features

- Automated backups using cron jobs
- Real-time progress monitoring of backup creation
- Secure login with session management
- Downloadable backup files
- Configurable backup directories and storage path

## Prerequisites

- Go
- `htpasswd` utility for generating bcrypt password hashes

## Setup

### Step 1: Clone the Repository

```sh
git clone https://github.com/vxfemboy/backup-webapp.git
cd backup-webapp
```

### Step 2: Generate a Bcrypt Password Hash

Generate a bcrypt password hash using the `htpasswd` utility:

```sh
htpasswd -nbBC 10 "" "password" | cut -d ':' -f 2
```

Replace `"password"` with your desired password. Copy the generated hash for use in the configuration file.

### Step 3: Configure the Application

Create a `config.toml` file based on the provided example:

```sh
cp config.toml.example config.toml
```

Edit the `config.toml` file to match your environment and preferences:

```toml
# config.toml
[server]
host = "127.0.0.1"           # Domain or IP address
port = 8443                  # Port number for the backup system
use_tls = false              # Set to true to enable HTTPS
base_url = "/backup"         # Base URL for the backup system

[tls]
cert_file = "fullchain.pem"  # Path to the certificate file
key_file = "privkey.pem"     # Path to the private key file

[backup]
dirs = [
    "/path/to/project1",
    "/path/to/project2",
]                            # Directories to backup

storage_path = "./backups/"  # Path to store backup files
backup_prefix = "backup"     # Prefix for backup filenames

[auth]
password_hash = "XXXXXXXXX"  # Password hash in bcrypt (replace with your generated hash)
session_timeout = 604800     # Session timeout in seconds
```

### Step 4: Build and Run the Application

Build the application:

```sh
go build -o backup-webapp ./src/main.go
```

Run the application:

```sh
./backup-webapp
```

### Step 5: Access the Web Interface

Open your web browser and navigate to the configured host and port (e.g., `http://127.0.0.1:8443/backup`). You will be prompted to log in using the password you configured.

## Usage

### Creating a Backup

1. Log in to the web interface.
2. Click the "Create New Backup" button.
3. Monitor the progress of the backup creation in real-time.
4. Once the backup is complete, it will be listed on the main page.

### Downloading a Backup

1. Log in to the web interface.
2. Find the desired backup in the list.
3. Click the "Download" button next to the backup file.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.
