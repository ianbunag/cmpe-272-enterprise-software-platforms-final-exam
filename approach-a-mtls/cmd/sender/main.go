package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	chunkSize      = 32 * 1024
	progressEvery  = 100 * 1024 * 1024
	maxRetries     = 5
	baseRetryDelay = time.Second
	maxRetryDelay  = 30 * time.Second
)

type transferHeader struct {
	Filename       string `json:"filename"`
	ExpectedSHA256 string `json:"expected_sha256"`
	FileSize       int64  `json:"file_size"`
}

func main() {
	filePath   := flag.String("file", "", "path to the file to send")
	addr       := flag.String("addr", "localhost:9090", "receiver address")
	caPath     := flag.String("ca", "", "path to Root CA certificate")
	certPath   := flag.String("cert", "", "path to sender certificate")
	keyPath    := flag.String("key", "", "path to sender private key")
	serverName := flag.String("server-name", "receiver", "TLS server name to verify against receiver certificate")
	flag.Parse()

	if *filePath == "" || *caPath == "" || *certPath == "" || *keyPath == "" {
		log.Fatal("flags file, ca, cert and key are required")
	}

	log.Printf("computing SHA-256 hash of %s", *filePath)
	fileHash, fileSize, err := hashFile(*filePath)
	if err != nil {
		log.Fatalf("hash file error %v", err)
	}
	log.Printf("file size %d bytes hash %s", fileSize, fileHash)

	tlsCfg, err := buildTLSConfig(*caPath, *certPath, *keyPath, *serverName)
	if err != nil {
		log.Fatalf("TLS config error %v", err)
	}

	conn, err := dialWithRetry(*addr, tlsCfg)
	if err != nil {
		log.Fatalf("connect error %v", err)
	}
	defer conn.Close()

	hdr := transferHeader{
		Filename:       filepath.Base(*filePath),
		ExpectedSHA256: fileHash,
		FileSize:       fileSize,
	}

	if err := sendFile(conn, *filePath, hdr, fileSize); err != nil {
		log.Fatalf("send error %v", err)
	}

	log.Printf("transfer complete")
}

func buildTLSConfig(caPath, certPath, keyPath, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key pair %w", err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA certificate failed")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func dialWithRetry(addr string, cfg *tls.Config) (net.Conn, error) {
	delay := baseRetryDelay
	for attempt := 1; attempt <= maxRetries; attempt++ {
		conn, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			log.Printf("connected to %s", addr)
			return conn, nil
		}
		if attempt == maxRetries {
			return nil, fmt.Errorf("failed after %d attempts %w", maxRetries, err)
		}
		log.Printf("connection attempt %d of %d failed %v retrying in %s", attempt, maxRetries, err, delay)
		time.Sleep(delay)
		delay *= 2
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}
	}
	return nil, fmt.Errorf("unreachable")
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %w", err)
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, chunkSize)
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

func sendFile(conn net.Conn, filePath string, hdr transferHeader, fileSize int64) error {
	bw := bufio.NewWriterSize(conn, chunkSize)

	headerBytes, err := json.Marshal(hdr)
	if err != nil {
		return fmt.Errorf("marshal header %w", err)
	}
	headerBytes = append(headerBytes, '\n')
	if _, err := bw.Write(headerBytes); err != nil {
		return fmt.Errorf("write header %w", err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file %w", err)
	}
	defer f.Close()

	buf          := make([]byte, chunkSize)
	var sent     int64
	var lastSent int64
	nextMilestone := int64(progressEvery)
	start        := time.Now()
	lastTime     := start

	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := bw.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write chunk %w", werr)
			}
			sent += int64(n)

			if sent >= nextMilestone {
				now      := time.Now()
				elapsed  := now.Sub(lastTime).Seconds()
				chunkMB  := float64(sent-lastSent) / (1024 * 1024)
				pct      := float64(sent) / float64(fileSize) * 100
				log.Printf("progress %.1f%% sent %d MB throughput %.2f MB/s",
					pct, sent/(1024*1024), chunkMB/elapsed)
				lastTime      = now
				lastSent      = sent
				nextMilestone += progressEvery
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read file %w", err)
		}
	}

	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush %w", err)
	}

	totalMB  := float64(sent) / (1024 * 1024)
	totalSec := time.Since(start).Seconds()
	log.Printf("sent %d bytes (%.1f MB) in %.1f seconds average %.2f MB/s",
		sent, totalMB, totalSec, totalMB/totalSec)

	return nil
}
