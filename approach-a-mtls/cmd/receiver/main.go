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
	"strings"
)

const chunkSize = 32 * 1024

type transferHeader struct {
	Filename       string `json:"filename"`
	ExpectedSHA256 string `json:"expected_sha256"`
	FileSize       int64  `json:"file_size"`
}

func main() {
	addr     := flag.String("addr", ":9090", "TCP address to listen on")
	caPath   := flag.String("ca", "", "path to Root CA certificate")
	certPath := flag.String("cert", "", "path to receiver certificate")
	keyPath  := flag.String("key", "", "path to receiver private key")
	outDir   := flag.String("out", ".", "directory to write received files")
	flag.Parse()

	if *caPath == "" || *certPath == "" || *keyPath == "" {
		log.Fatal("flags ca, cert and key are required")
	}

	tlsCfg, err := buildTLSConfig(*caPath, *certPath, *keyPath)
	if err != nil {
		log.Fatalf("TLS config error %v", err)
	}

	ln, err := tls.Listen("tcp", *addr, tlsCfg)
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
		go handleConnection(conn, *outDir)
	}
}

func buildTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func handleConnection(conn net.Conn, outDir string) {
	defer conn.Close()

	br := bufio.NewReaderSize(conn, chunkSize)

	line, err := br.ReadString('\n')
	if err != nil {
		log.Printf("read header error %v", err)
		return
	}

	var hdr transferHeader
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &hdr); err != nil {
		log.Printf("parse header error %v", err)
		return
	}

	safeFilename := filepath.Base(hdr.Filename)
	tmpPath      := filepath.Join(outDir, safeFilename+".tmp")
	finalPath    := filepath.Join(outDir, safeFilename)

	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		log.Printf("create temp file error %v", err)
		return
	}

	success := false
	defer func() {
		tmpFile.Close()
		if !success {
			os.Remove(tmpPath)
			log.Printf("partial file removed from %s", tmpPath)
		}
	}()

	hash   := sha256.New()
	buf    := make([]byte, chunkSize)
	writer := io.MultiWriter(tmpFile, hash)

	var received int64
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if _, werr := writer.Write(buf[:n]); werr != nil {
				log.Printf("write error %v", werr)
				return
			}
			received += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("read stream error %v", err)
			return
		}
	}

	if hdr.FileSize > 0 && received != hdr.FileSize {
		log.Printf("size mismatch expected %d got %d", hdr.FileSize, received)
		return
	}

	got := hex.EncodeToString(hash.Sum(nil))
	if got != hdr.ExpectedSHA256 {
		log.Printf("hash mismatch expected %s got %s", hdr.ExpectedSHA256, got)
		return
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		log.Printf("rename error %v", err)
		return
	}

	success = true
	log.Printf("transfer complete. file saved to %s sha256 verified", finalPath)
}
