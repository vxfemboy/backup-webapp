package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Server struct {
		Host    string `toml:"host"`
		Port    int    `toml:"port"`
		UseTLS  bool   `toml:"use_tls"`
		BaseURL string `toml:"base_url"`
	} `toml:"server"`
	TLS struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"tls"`
	Backup struct {
		Dirs         []string `toml:"dirs"`
		StoragePath  string   `toml:"storage_path"`
		BackupPrefix string   `toml:"backup_prefix"`
		CronSchedule string   `toml:"cron_schedule"`
	} `toml:"backup"`
	Auth struct {
		PasswordHash   string `toml:"password_hash"`
		SessionTimeout int    `toml:"session_timeout"`
	} `toml:"auth"`
}

type BackupProgress struct {
	Filename   string  `json:"filename"`
	Percentage float64 `json:"percentage"`
	Status     string  `json:"status"`
}

type BackupState struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	StartTime  time.Time `json:"start_time"`
	Status     string    `json:"status"`
	Percentage float64   `json:"percentage"`
}

type BackupManager struct {
	activeBackups map[string]*BackupState
	mu            sync.RWMutex
}

type ProgressWriter struct {
	current    int64
	total      int64
	lastUpdate time.Time
	backupID   string
	clientChan chan BackupProgress
	filename   string
	done       chan struct{}
	mu         sync.Mutex
}

var (
	backupManager = &BackupManager{
		activeBackups: make(map[string]*BackupState),
	}
)

var (
	config Config
	aesKey []byte
)

func init() {
	// Generate AES-256 key from password hash
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal(err)
	}
	aesKey = key
}

func encryptToken(data []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptToken(token string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid token")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth check for login page
		loginURL := fmt.Sprintf("%s/login", config.Server.BaseURL)
		if c.Request.URL.Path == loginURL {
			c.Next()
			return
		}

		// Check for session cookie
		token, err := c.Cookie("session")
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, loginURL)
			c.Abort()
			return
		}

		// Validate token
		data, err := decryptToken(token)
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, loginURL)
			c.Abort()
			return
		}

		// Check token expiry
		timestamp := string(data)
		expiry, err := time.Parse(time.RFC3339, timestamp)
		if err != nil || time.Now().After(expiry) {
			c.Redirect(http.StatusTemporaryRedirect, loginURL)
			c.Abort()
			return
		}

		c.Next()
	}
}

func handleLogin(c *gin.Context) {
	if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "login.html", nil)
		return
	}

	password := c.PostForm("password")
	if err := bcrypt.CompareHashAndPassword([]byte(config.Auth.PasswordHash), []byte(password)); err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid password"})
		return
	}

	// Create session token
	expiry := time.Now().Add(time.Duration(config.Auth.SessionTimeout) * time.Second)
	token, err := encryptToken([]byte(expiry.Format(time.RFC3339)))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{"error": "Server error"})
		return
	}

	// Set session cookie
	c.SetCookie("session", token, config.Auth.SessionTimeout, config.Server.BaseURL, "", false, true)

	// Use 303 See Other instead of 307 to force a GET request
	c.Redirect(http.StatusSeeOther, config.Server.BaseURL)
}

func main() {
	// Load configuration
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatal(err)
	}

	// Ensure backup storage directory exists
	if err := os.MkdirAll(config.Backup.StoragePath, 0755); err != nil {
		log.Fatalf("Failed to create backup storage directory: %v", err)
	}

	// Setup cron for backups
	c := cron.New()
	cronSchedule := config.Backup.CronSchedule
	if _, err := cron.ParseStandard(config.Backup.CronSchedule); err != nil {
		log.Fatalf("Invalid Cron Expression %v", err)
	}
	c.AddFunc(cronSchedule, func() {
		if _, err := createBackup(); err != nil {
			log.Printf("Backup failed: %v", err)
		}
	})
	c.Start()

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Load templates
	router.LoadHTMLGlob("templates/*")

	// Setup routes with auth middleware
	backupGroup := router.Group(config.Server.BaseURL, authMiddleware())
	{
		backupGroup.GET("/", handleBackupList)
		backupGroup.GET("/create", handleCreateBackup)
		backupGroup.POST("/create", handleCreateBackup)
		backupGroup.GET("/download/:filename", handleDownload)
	}

	// Login route
	router.GET(fmt.Sprintf("%s/login", config.Server.BaseURL), handleLogin)
	router.POST(fmt.Sprintf("%s/login", config.Server.BaseURL), handleLogin)

	// Start server
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	if config.Server.UseTLS {
		log.Printf("Starting HTTPS server on %s", addr)
		log.Fatal(router.RunTLS(addr, config.TLS.CertFile, config.TLS.KeyFile))
	} else {
		log.Printf("Starting HTTP server on %s", addr)
		log.Fatal(router.Run(addr))
	}
}

func (bm *BackupManager) StartBackup() *BackupState {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	id := uuid.New().String()
	state := &BackupState{
		ID:        id,
		StartTime: time.Now(),
		Status:    "initializing",
	}
	bm.activeBackups[id] = state
	return state
}

func (bm *BackupManager) UpdateBackup(id string, filename string, percentage float64, status string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if state, exists := bm.activeBackups[id]; exists {
		state.Filename = filename
		state.Percentage = percentage
		state.Status = status

		// Clean up completed or failed backups after some time
		if status == "completed" || status == "error" {
			go func(backupID string) {
				time.Sleep(5 * time.Minute)
				bm.mu.Lock()
				delete(bm.activeBackups, backupID)
				bm.mu.Unlock()
			}(id)
		}
	}
}

func (bm *BackupManager) GetBackup(id string) *BackupState {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.activeBackups[id]
}

func (bm *BackupManager) GetActiveBackup() *BackupState {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for _, state := range bm.activeBackups {
		if state.Status != "completed" && state.Status != "error" {
			return state
		}
	}
	return nil
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.mu.Lock()
	pw.current += int64(n)
	pw.mu.Unlock()

	// Update progress at regular intervals (e.g., every second)
	if time.Since(pw.lastUpdate) >= time.Second {
		pw.sendProgressUpdate()
		pw.lastUpdate = time.Now()
	}

	return n, nil
}
func (pw *ProgressWriter) sendProgressUpdate() {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	percentage := float64(pw.current) / float64(pw.total) * 100
	select {
	case <-pw.done:
		return
	case pw.clientChan <- BackupProgress{
		Status:     "compressing",
		Filename:   pw.filename,
		Percentage: percentage,
	}:
	default:
		// Channel is full, skip this update
	}
}

func handleBackupList(c *gin.Context) {
	entries, err := os.ReadDir(config.Backup.StoragePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() {
			backups = append(backups, entry.Name())
		}
	}

	// Get any active backup
	activeBackup := backupManager.GetActiveBackup()

	c.HTML(http.StatusOK, "list.html", gin.H{
		"backups":      backups,
		"activeBackup": activeBackup,
	})
}

func handleCreateBackup(c *gin.Context) {
	if c.GetHeader("Accept") == "text/event-stream" {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")

		clientChan := make(chan BackupProgress, 10)
		doneChan := make(chan struct{})

		go func() {
			filename, err := createBackupWithProgress(clientChan, doneChan)
			if err != nil {
				clientChan <- BackupProgress{
					Status:   "error",
					Filename: err.Error(),
				}
			} else {
				clientChan <- BackupProgress{
					Status:     "completed",
					Filename:   filename,
					Percentage: 100,
				}
			}
			close(clientChan)
		}()

		c.Stream(func(w io.Writer) bool {
			select {
			case progress, ok := <-clientChan:
				if !ok {
					return false
				}
				c.SSEvent("progress", progress)
				return true
			case <-c.Request.Context().Done():
				close(doneChan)
				return false
			}
		})
	} else {
		filename, err := createBackup()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"filename": filename})
	}
}

func handleDownload(c *gin.Context) {
	filename := c.Param("filename")
	filePath := filepath.Join(config.Backup.StoragePath, filename)

	// Security check: ensure the file is within the backup directory
	if !isFileInDir(filePath, config.Backup.StoragePath) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	c.File(filePath)
}

func createBackup() (string, error) {
	date := time.Now().Format("02-01-2006T15:04:05")
	filename := fmt.Sprintf("%s-%s.tar.gz", config.Backup.BackupPrefix, date)
	backupPath := filepath.Join(config.Backup.StoragePath, filename)

	file, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %v", err)
	}
	defer file.Close()

	gw := gzip.NewWriter(file)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add each directory to the archive
	for _, dir := range config.Backup.Dirs {
		absPath, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("failed to get absolute path: %v", err)
		}

		baseDir := filepath.Dir(absPath)
		err = filepath.WalkDir(absPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("failed to get file info: %v", err)
			}

			// Create header
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return fmt.Errorf("failed to create tar header: %v", err)
			}

			// Set relative path in the archive
			relPath, err := filepath.Rel(baseDir, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path: %v", err)
			}
			header.Name = relPath

			if err := tw.WriteHeader(header); err != nil {
				return fmt.Errorf("failed to write tar header: %v", err)
			}

			if !info.Mode().IsRegular() {
				return nil
			}

			// Copy file content
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file: %v", err)
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return fmt.Errorf("failed to copy file content: %v", err)
			}

			return nil
		})

		if err != nil {
			return "", fmt.Errorf("failed to walk directory %s: %v", dir, err)
		}
	}

	return filename, nil
}

func createBackupWithProgress(clientChan chan BackupProgress, done chan struct{}) (string, error) {
	date := time.Now().Format("02-01-2006T15:04:05")
	filename := fmt.Sprintf("%s-%s.tar.gz", config.Backup.BackupPrefix, date)
	backupPath := filepath.Join(config.Backup.StoragePath, filename)

	// Start backup tracking
	state := backupManager.StartBackup()
	state.Filename = filename
	state.Status = "starting"

	// Notify starting
	clientChan <- BackupProgress{
		Status:   "starting",
		Filename: filename,
	}

	file, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %v", err)
	}
	defer file.Close()

	// Calculate total size
	var totalSize int64
	for _, dir := range config.Backup.Dirs {
		size, err := getDirSize(dir)
		if err != nil {
			return "", fmt.Errorf("failed to calculate directory size: %v", err)
		}
		totalSize += size
	}

	// Create progress writer
	progressWriter := &ProgressWriter{
		current:    0,
		total:      totalSize,
		lastUpdate: time.Now(),
		backupID:   state.ID,
		clientChan: clientChan,
		filename:   filename,
		done:       done,
	}

	// Create a multi-writer to write to both file and progress tracker
	mw := io.MultiWriter(file, progressWriter)

	// Start compression in a goroutine
	errChan := make(chan error, 1)
	go func() {
		gw := gzip.NewWriter(mw)
		tw := tar.NewWriter(gw)

		// Add each directory to the archive
		for _, dir := range config.Backup.Dirs {
			absPath, err := filepath.Abs(dir)
			if err != nil {
				errChan <- fmt.Errorf("failed to get absolute path: %v", err)
				return
			}

			dirName := filepath.Base(absPath)

			err = filepath.WalkDir(absPath, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}

				info, err := d.Info()
				if err != nil {
					return fmt.Errorf("failed to get file info: %v", err)
				}

				relPath, err := filepath.Rel(absPath, path)
				if err != nil {
					return fmt.Errorf("failed to get relative path: %v", err)
				}

				header, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return fmt.Errorf("failed to create tar header: %v", err)
				}

				header.Name = filepath.Join(dirName, relPath)

				if err := tw.WriteHeader(header); err != nil {
					return fmt.Errorf("failed to write tar header: %v", err)
				}

				if !info.Mode().IsRegular() {
					return nil
				}

				file, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open file: %v", err)
				}
				defer file.Close()

				if _, err := io.Copy(tw, file); err != nil {
					return fmt.Errorf("failed to copy file content: %v", err)
				}

				return nil
			})

			if err != nil {
				errChan <- fmt.Errorf("failed to walk directory %s: %v", dir, err)
				return
			}
		}

		// Close writers in correct order
		if err := tw.Close(); err != nil {
			errChan <- fmt.Errorf("failed to close tar writer: %v", err)
			return
		}
		if err := gw.Close(); err != nil {
			errChan <- fmt.Errorf("failed to close gzip writer: %v", err)
			return
		}
		errChan <- nil
	}()

	// Wait for compression to complete
	if err := <-errChan; err != nil {
		return "", err
	}

	// Send final progress update
	progressWriter.sendProgressUpdate()

	// Update final status
	backupManager.UpdateBackup(state.ID, filename, 100, "completed")

	return filename, nil
}

func isFileInDir(filePath, dir string) bool {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}
	fileDir := filepath.Dir(absFile)
	return fileDir == absDir
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
}
