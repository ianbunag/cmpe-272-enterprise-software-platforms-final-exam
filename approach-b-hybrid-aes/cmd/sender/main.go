package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	chunkSize      = 1 * 1024 * 1024
	progressEvery  = 100 * 1024 * 1024
	maxRetries     = 5
	baseRetryDelay = time.Second
	maxRetryDelay  = 30 * time.Second
)

type sessionInfo struct {
	Filename       string `json:"filename"`
	FileSize       int64  `json:"file_size"`
	TotalChunks    int64  `json:"total_chunks"`
	ChunkSize      int    `json:"chunk_size"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type sessionFile struct {
	SessionIDHex string `json:"session_id_hex"`
	Filename     string `json:"filename"`
}

func main() {
	filePath    := flag.String("file", "", "path to the file to send")
	addr        := flag.String("addr", "receiver:9000", "receiver address")
	recvPubPath := flag.String("receiver-pub", "", "path to receiver RSA public key PEM")
	senderKey   := flag.String("key", "", "path to sender RSA private key PEM")
	sessionDir  := flag.String("session-dir", ".", "directory for session state files")
	flag.Parse()

	if *filePath == "" || *recvPubPath == "" || *senderKey == "" {
		log.Fatal("flags file, receiver-pub and key are required")
	}

	recvPub, err := loadPublicKey(*recvPubPath)
	if err != nil {
		log.Fatalf("load receiver public key error %v", err)
	}

	sndKey, err := loadPrivateKey(*senderKey)
	if err != nil {
		log.Fatalf("load sender private key error %v", err)
	}

	log.Printf("computing SHA-256 hash of %s", *filePath)
	fileHash, fileSize, err := hashFile(*filePath)
	if err != nil {
		log.Fatalf("hash file error %v", err)
	}
	log.Printf("file size %d bytes hash %s", fileSize, fileHash)

	totalChunks := (fileSize + chunkSize - 1) / chunkSize

	info := sessionInfo{
		Filename:       filepath.Base(*filePath),
		FileSize:       fileSize,
		TotalChunks:    totalChunks,
		ChunkSize:      chunkSize,
		ExpectedSHA256: fileHash,
	}

	// Load the session ID from a prior run or generate a fresh one.
	// Persisting the session ID is what allows the receiver to match a reconnect
	// to a prior partial transfer and offer a non-zero resume offset.
	sessionID, err := loadOrCreateSession(*sessionDir, info.Filename)
	if err != nil {
		log.Fatalf("session init error %v", err)
	}
	log.Printf("session %s", hex.EncodeToString(sessionID)[:8])

	if err := runTransfer(*addr, *filePath, sessionID, info, recvPub, sndKey); err != nil {
		log.Fatalf("transfer failed %v", err)
	}

	sessionPath := filepath.Join(*sessionDir, info.Filename+".session")
	os.Remove(sessionPath)
	log.Printf("transfer complete")
}

func runTransfer(addr, filePath string, sessionID []byte, info sessionInfo, recvPub *rsa.PublicKey, sndKey *rsa.PrivateKey) error {
	delay := baseRetryDelay
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := doSession(addr, filePath, sessionID, info, recvPub, sndKey)
		if err == nil {
			return nil
		}
		if attempt == maxRetries {
			return fmt.Errorf("failed after %d attempts %w", maxRetries, err)
		}
		log.Printf("attempt %d of %d failed %v retrying in %s", attempt, maxRetries, err, delay)
		time.Sleep(delay)
		delay *= 2
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}
	}
	return fmt.Errorf("unreachable")
}

func doSession(addr, filePath string, sessionID []byte, info sessionInfo, recvPub *rsa.PublicKey, sndKey *rsa.PrivateKey) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect %w", err)
	}
	defer conn.Close()
	log.Printf("connected to %s", addr)

	// Generate a fresh AES-256 session key for this connection.
	// Using a fresh key per connection segment means a captured ciphertext from one
	// segment cannot be decrypted using the key from any other segment, providing
	// per-connection forward secrecy. The session ID (not the AES key) is what
	// ties reconnects to the same partial transfer on the receiver side.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("generate AES key %w", err)
	}

	// Encrypt the AES key and session ID together under the receiver's public key
	// using RSA-OAEP with SHA-256. Only the receiver holding the matching private key
	// can unwrap the session key.
	envelope := make([]byte, 48)
	copy(envelope[0:32], aesKey)
	copy(envelope[32:48], sessionID)

	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recvPub, envelope, nil)
	if err != nil {
		return fmt.Errorf("RSA-OAEP encrypt %w", err)
	}
	if err := writeFrame(conn, rsaCiphertext); err != nil {
		return fmt.Errorf("send RSA envelope %w", err)
	}

	// Sign the RSA ciphertext with the sender's private key using RSA-PSS with SHA-256.
	// The receiver verifies this signature to confirm the sender's identity before
	// accepting any data. This is the mutual authentication fix: possession of the
	// receiver's public key alone is not sufficient to pass this check.
	digest := sha256.Sum256(rsaCiphertext)
	sig, err := rsa.SignPSS(rand.Reader, sndKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return fmt.Errorf("sign envelope %w", err)
	}
	if err := writeFrame(conn, sig); err != nil {
		return fmt.Errorf("send signature %w", err)
	}

	// Build and send the AES-GCM encrypted session info header.
	// A random 12-byte nonce is generated per connection and prepended to the ciphertext
	// so the receiver can decrypt it. This nonce is distinct from the chunk nonces which
	// are derived from the chunk index and never sent on the wire.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("AES cipher %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("GCM init %w", err)
	}

	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal session info %w", err)
	}
	infoNonce := make([]byte, 12)
	if _, err := rand.Read(infoNonce); err != nil {
		return fmt.Errorf("generate info nonce %w", err)
	}
	infoFrame := append(infoNonce, gcm.Seal(nil, infoNonce, infoJSON, nil)...)
	if err := writeFrame(conn, infoFrame); err != nil {
		return fmt.Errorf("send session info %w", err)
	}

	// Read the resume chunk index sent by the receiver.
	var resumeBuf [8]byte
	if _, err := io.ReadFull(conn, resumeBuf[:]); err != nil {
		return fmt.Errorf("read resume offset %w", err)
	}
	resumeChunk := int64(binary.BigEndian.Uint64(resumeBuf[:]))
	if resumeChunk > 0 {
		log.Printf("resuming from chunk %d of %d", resumeChunk, info.TotalChunks)
	}

	return sendChunks(conn, filePath, gcm, resumeChunk, info)
}

func sendChunks(conn net.Conn, filePath string, gcm cipher.AEAD, resumeChunk int64, info sessionInfo) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file %w", err)
	}
	defer f.Close()

	if resumeChunk > 0 {
		if _, err := f.Seek(resumeChunk*chunkSize, io.SeekStart); err != nil {
			return fmt.Errorf("seek to resume position %w", err)
		}
	}

	var (
		chunkIdx      = resumeChunk
		bytesSent     = resumeChunk * chunkSize
		lastLogged    = bytesSent
		nextMilestone = ((bytesSent / progressEvery) + 1) * progressEvery
		start         = time.Now()
		lastTime      = start
		buf           = make([]byte, chunkSize)
	)

	for chunkIdx < info.TotalChunks {
		n, err := io.ReadFull(f, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("read chunk %d %w", chunkIdx, err)
		}

		nonce      := chunkNonce(chunkIdx)
		ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)

		if err := writeFrame(conn, ciphertext); err != nil {
			return fmt.Errorf("send chunk %d %w", chunkIdx, err)
		}

		chunkIdx++
		bytesSent += int64(n)

		if bytesSent >= nextMilestone {
			now     := time.Now()
			elapsed := now.Sub(lastTime).Seconds()
			mbChunk := float64(bytesSent-lastLogged) / (1024 * 1024)
			pct     := float64(bytesSent) / float64(info.FileSize) * 100
			log.Printf("progress %.1f%% sent %d MB throughput %.2f MB/s",
				pct, bytesSent/(1024*1024), mbChunk/elapsed)
			lastTime      = now
			lastLogged    = bytesSent
			nextMilestone += progressEvery
		}
	}

	totalMB  := float64(bytesSent) / (1024 * 1024)
	totalSec := time.Since(start).Seconds()
	log.Printf("sent %.1f MB in %.1f seconds average %.2f MB/s",
		totalMB, totalSec, totalMB/totalSec)
	return nil
}

// chunkNonce derives a 12-byte AES-GCM nonce from the chunk index.
// Bytes 0 through 3 are zero and bytes 4 through 11 hold the big-endian uint64 index.
// This matches the nonce derivation in the receiver so no nonce is transmitted for chunks.
func chunkNonce(index int64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], uint64(index))
	return nonce
}

// writeFrame writes a 4-byte big-endian length prefix followed by the payload.
func writeFrame(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload %w", err)
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %w", err)
	}
	defer f.Close()

	h   := sha256.New()
	buf := make([]byte, 32*1024)
	var size int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			size += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("read %w", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func loadOrCreateSession(sessionDir, filename string) ([]byte, error) {
	sessionPath := filepath.Join(sessionDir, filename+".session")

	data, err := os.ReadFile(sessionPath)
	if err == nil {
		var sf sessionFile
		if json.Unmarshal(data, &sf) == nil && sf.Filename == filename && sf.SessionIDHex != "" {
			sessionID, err := hex.DecodeString(sf.SessionIDHex)
			if err == nil && len(sessionID) == 16 {
				log.Printf("loaded existing session from %s", sessionPath)
				return sessionID, nil
			}
		}
	}

	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("generate session ID %w", err)
	}

	sf := sessionFile{
		SessionIDHex: hex.EncodeToString(sessionID),
		Filename:     filename,
	}
	sfData, err := json.Marshal(sf)
	if err != nil {
		return nil, fmt.Errorf("marshal session file %w", err)
	}
	if err := os.WriteFile(sessionPath, sfData, 0644); err != nil {
		return nil, fmt.Errorf("write session file %w", err)
	}
	return sessionID, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not RSA", path)
	}
	return rsaKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not RSA", path)
	}
	return rsaPub, nil
}
