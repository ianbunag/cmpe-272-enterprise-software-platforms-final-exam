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
	progressEvery = 100 * 1024 * 1024
	maxFrameBytes = 64 * 1024 * 1024
)

type sessionInfo struct {
	Filename       string `json:"filename"`
	FileSize       int64  `json:"file_size"`
	TotalChunks    int64  `json:"total_chunks"`
	ChunkSize      int    `json:"chunk_size"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type sessionState struct {
	SessionIDHex   string `json:"session_id_hex"`
	Filename       string `json:"filename"`
	FileSize       int64  `json:"file_size"`
	TotalChunks    int64  `json:"total_chunks"`
	ChunkSize      int    `json:"chunk_size"`
	ChunksVerified int64  `json:"chunks_verified"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

func main() {
	addr := flag.String("addr", ":9000", "TCP address to listen on")
	receiverKey := flag.String("key", "", "path to receiver RSA private key PEM")
	senderPubPath := flag.String("sender-pub", "", "path to sender RSA public key PEM")
	outDir := flag.String("out", ".", "directory to write received files")
	flag.Parse()

	if *receiverKey == "" || *senderPubPath == "" {
		log.Fatal("flags key and sender-pub are required")
	}

	privKey, err := loadPrivateKey(*receiverKey)
	if err != nil {
		log.Fatalf("load receiver private key error %v", err)
	}

	senderPub, err := loadPublicKey(*senderPubPath)
	if err != nil {
		log.Fatalf("load sender public key error %v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen error %v", err)
	}
	defer ln.Close()
	log.Printf("receiver listening on %s", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error %v", err)
			continue
		}
		go handleConnection(conn, privKey, senderPub, *outDir)
	}
}

func handleConnection(conn net.Conn, privKey *rsa.PrivateKey, senderPub *rsa.PublicKey, outDir string) {
	defer conn.Close()
	log.Printf("connection accepted from %s", conn.RemoteAddr())

	// Read the RSA-OAEP encrypted envelope containing the AES session key and session ID.
	// The envelope is decrypted with the receiver's private key so only this receiver
	// can unwrap the session key.
	rsaCiphertext, err := readFrame(conn)
	if err != nil {
		log.Printf("read RSA envelope error %v", err)
		return
	}

	envelopePlain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, rsaCiphertext, nil)
	if err != nil {
		log.Printf("RSA-OAEP decrypt error %v", err)
		return
	}
	if len(envelopePlain) != 48 {
		log.Printf("envelope plaintext length %d is unexpected", len(envelopePlain))
		return
	}

	aesKey := envelopePlain[0:32]
	sessionID := envelopePlain[32:48]
	sessionIDHex := hex.EncodeToString(sessionID)

	// Read and verify the sender's RSA-PSS signature over the RSA ciphertext bytes.
	// This proves the sender holds the private key paired with the known sender public key
	// and provides mutual authentication. Without this step any party that obtains the
	// receiver public key could initiate a session.
	sigBytes, err := readFrame(conn)
	if err != nil {
		log.Printf("read sender signature error %v", err)
		return
	}

	digest := sha256.Sum256(rsaCiphertext)
	if err := rsa.VerifyPSS(senderPub, crypto.SHA256, digest[:], sigBytes, nil); err != nil {
		log.Printf("sender signature verification failed %v", err)
		return
	}
	log.Printf("sender identity verified for session %s", sessionIDHex[:8])

	// Read and decrypt the session info header using AES-256-GCM.
	// The 12-byte random nonce is prepended to the ciphertext in the frame.
	infoFrame, err := readFrame(conn)
	if err != nil {
		log.Printf("read session info frame error %v", err)
		return
	}
	if len(infoFrame) < 12 {
		log.Printf("session info frame too short")
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Printf("AES cipher init error %v", err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("GCM init error %v", err)
		return
	}

	infoNonce := infoFrame[:12]
	infoCiphertext := infoFrame[12:]
	infoPlain, err := gcm.Open(nil, infoNonce, infoCiphertext, nil)
	if err != nil {
		log.Printf("decrypt session info error %v", err)
		return
	}

	var info sessionInfo
	if err := json.Unmarshal(infoPlain, &info); err != nil {
		log.Printf("parse session info error %v", err)
		return
	}
	log.Printf("session %s receiving file %q size %d bytes in %d chunks",
		sessionIDHex[:8], info.Filename, info.FileSize, info.TotalChunks)

	// Determine the resume offset by checking for a persisted state file from a prior
	// interrupted transfer with the same session ID.
	statePath := filepath.Join(outDir, sessionIDHex+".state")
	tmpPath := filepath.Join(outDir, sessionIDHex+".tmp")
	finalPath := filepath.Join(outDir, filepath.Base(info.Filename))

	var resumeChunk int64
	if prior, err := loadState(statePath); err == nil {
		resumeChunk = prior.ChunksVerified
		log.Printf("resuming session %s from chunk %d of %d",
			sessionIDHex[:8], resumeChunk, info.TotalChunks)
	}

	var resumeBuf [8]byte
	binary.BigEndian.PutUint64(resumeBuf[:], uint64(resumeChunk))
	if _, err := conn.Write(resumeBuf[:]); err != nil {
		log.Printf("send resume offset error %v", err)
		return
	}

	// Open or create the temp file and seek to the write position for resumption.
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("open temp file error %v", err)
		return
	}

	success := false
	defer func() {
		tmpFile.Close()
		if !success {
			os.Remove(tmpPath)
			os.Remove(statePath)
			log.Printf("partial file removed")
		}
	}()

	if resumeChunk > 0 {
		seekPos := resumeChunk * int64(info.ChunkSize)
		if _, err := tmpFile.Seek(seekPos, io.SeekStart); err != nil {
			log.Printf("seek to resume position error %v", err)
			return
		}
	}

	// Receive, authenticate, and decrypt each chunk starting from resumeChunk.
	// The nonce for chunk i is derived from the chunk index so it is never reused
	// and never needs to be transmitted on the wire.
	var (
		chunkIdx      = resumeChunk
		bytesReceived = resumeChunk * int64(info.ChunkSize)
		lastLogged    = bytesReceived
		nextMilestone = ((bytesReceived / progressEvery) + 1) * progressEvery
		start         = time.Now()
		lastTime      = start
	)

	for chunkIdx < info.TotalChunks {
		ciphertext, err := readFrame(conn)
		if err != nil {
			log.Printf("read chunk %d error %v", chunkIdx, err)
			return
		}

		nonce := chunkNonce(chunkIdx)
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Printf("AEAD tag verification failed on chunk %d", chunkIdx)
			return
		}

		if _, err := tmpFile.Write(plaintext); err != nil {
			log.Printf("write chunk %d error %v", chunkIdx, err)
			return
		}

		chunkIdx++
		bytesReceived += int64(len(plaintext))

		state := sessionState{
			SessionIDHex:   sessionIDHex,
			Filename:       info.Filename,
			FileSize:       info.FileSize,
			TotalChunks:    info.TotalChunks,
			ChunkSize:      info.ChunkSize,
			ChunksVerified: chunkIdx,
			ExpectedSHA256: info.ExpectedSHA256,
		}
		if err := saveState(statePath, state); err != nil {
			log.Printf("save state error %v", err)
			return
		}

		if bytesReceived >= nextMilestone {
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()
			mbChunk := float64(bytesReceived-lastLogged) / (1024 * 1024)
			pct := float64(bytesReceived) / float64(info.FileSize) * 100
			log.Printf("progress %.1f%% received %d MB throughput %.2f MB/s",
				pct, bytesReceived/(1024*1024), mbChunk/elapsed)
			lastTime = now
			lastLogged = bytesReceived
			nextMilestone += progressEvery
		}
	}

	// Flush to disk before computing the end-to-end hash.
	if err := tmpFile.Sync(); err != nil {
		log.Printf("sync error %v", err)
		return
	}

	log.Printf("all chunks received. verifying end-to-end SHA-256")
	got, err := hashFile(tmpPath)
	if err != nil {
		log.Printf("hash file error %v", err)
		return
	}
	if got != info.ExpectedSHA256 {
		log.Printf("SHA-256 mismatch expected %s got %s", info.ExpectedSHA256, got)
		return
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		log.Printf("rename error %v", err)
		return
	}
	os.Remove(statePath)

	totalMB := float64(bytesReceived) / (1024 * 1024)
	totalSec := time.Since(start).Seconds()
	success = true
	log.Printf("transfer complete received %.1f MB in %.1f seconds average %.2f MB/s file saved to %s sha256 verified",
		totalMB, totalSec, totalMB/totalSec, finalPath)
}

// chunkNonce derives a 12-byte AES-GCM nonce from the chunk index.
// Bytes 0 through 3 are zero and bytes 4 through 11 hold the big-endian uint64 index.
// The header uses a random nonce sent on the wire so no collision is possible.
func chunkNonce(index int64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], uint64(index))
	return nonce
}

// readFrame reads a 4-byte big-endian length then exactly that many bytes.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read frame length %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		return nil, fmt.Errorf("zero-length frame")
	}
	if length > maxFrameBytes {
		return nil, fmt.Errorf("frame length %d exceeds cap", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read frame payload %w", err)
	}
	return buf, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %w", err)
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read %w", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

func loadState(path string) (*sessionState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s sessionState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveState(path string, s sessionState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
