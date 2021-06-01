package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	ssh "cyber/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func decryptFile(inputfile string, key string) {
	data, err := ioutil.ReadFile(inputfile)
	//fmt.Printf("Decrypted: %s\n", data)
	result := decryptfiles(key, data)
	//fmt.Printf("Decrypted: %s\n", result)
	fmt.Printf("Decrypted file was created with file permissions 0777\n")
	err = ioutil.WriteFile(inputfile, result, 0777)
	if err != nil {
		fmt.Printf("Unable to create decrypted file!\n")
		os.Exit(0)
	}
}

func encryptFile(inputfile string, key string) {
	data, err := readFromFile(inputfile) //Read the target file
	if err != nil {
		fmt.Printf("Unable to open the this file!\n")
		os.Exit(0)
	}
	ciphertext := encryptfiles(key, data)
	//fmt.Printf("%x\n", ciphertext)
	err = ioutil.WriteFile(inputfile, ciphertext, 0644)
	if err != nil {
		fmt.Printf("Unable to create encrypted file!\n")
		os.Exit(0)
	}
}

func encryptfiles(keystring string, text []byte) []byte {

	key := []byte(keystring)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	data := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext
}

func decryptfiles(keystring string, text []byte) []byte {

	key := []byte(keystring)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(text) < aes.BlockSize {
		fmt.Printf("Error!\n")
		os.Exit(0)
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Printf("Error: Bad Key!\n")
		os.Exit(0)
	}
	return data
}
func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decrypttext(cipherstring string, keystring string) string {
	// Byte array of the string
	ciphertext := []byte(cipherstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}

func encrypttext(plainstring, keystring string) string {
	// Byte array of the string
	plaintext := []byte(plainstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return string(ciphertext)
}

func readline() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}

func writeToFile(data, file string) {
	ioutil.WriteFile(file, []byte(data), 0644)
}

func readFromFile(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}

func CheckErr(str string, err error) {
	if err != nil {
		fmt.Printf("%s: %s\n", str, err.Error())
		os.Exit(1)
	}
}

func main() {
	key, err := ssh.GenerateKey()
	CheckErr("generate key", err)
	for {
		fmt.Print("What would you like to do? ")
		line := readline()

		switch line {
		case "help":
			fmt.Println("You can:\nencrypt\ndecrypt\nexit")
		case "exit":
			err := os.Remove("private.pem")

			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("File todo.tmpl successfully deleted")
			os.Exit(0)
		case "encrypt":
			fmt.Println("What would you like to encrypt: ")
			fmt.Print("text\nelse ?")
			line2 := readline()
			switch line2 {
			case "text":
				ssh.PrivateandPublic()
				fmt.Print("What is the name of the file to encrypt: ")
				filename := readline()
				if plaintext, err := readFromFile(filename); err != nil {
					fmt.Println("File is not found")
				} else {
					ciphertext := encrypttext(string(plaintext), key)
					ioutil.WriteFile("ciphertext.txt", []byte(ciphertext), 0644)
					fmt.Print("Would you like to sign this file (Y:N): ")
					ans := readline()
					switch ans {
					case "Y":
						hashcipher := ssh.Hashcipher(ciphertext)
						fmt.Println(ciphertext)
						fmt.Println(hashcipher)
						ioutil.WriteFile("hashtext.txt", hashcipher, 0644)
						signmessage, err := ssh.SDigest(hashcipher)
						if err != nil {
							fmt.Println(err, signmessage)
						}
						ioutil.WriteFile("signedtext.txt", signmessage, 0644)
						fmt.Println("sign::", signmessage)
						
					}
				
				}
			case "else":
				fmt.Print("What is the name of the file to encrypt: ")
				filename := readline()
				encryptFile(filename, key)
			}

		case "decrypt":
			fmt.Println("What would you like to encrypt: ")
			fmt.Print("ciphertext\nsignedtext\nelse ?")
			types := readline()
			switch types {
			case "signedtext":
				err := ssh.VerifyDG()
				if err != nil {
					fmt.Println("Checksum error:", err)
				} else {
					fmt.Println("Verify correct: Data not changed naka")
				}
            case "ciphertext":
				fmt.Print("What is the name of the file to decrypt: ")
				filename := readline()
				if ciphertext, err := readFromFile(filename); err != nil {
					fmt.Println("File is not found")
				} else { 
					plaintext := decrypttext(string(ciphertext), key)
					ioutil.WriteFile("ciphertext.txt", []byte(plaintext), 0644)
				}
				
			case "else":
				fmt.Print("What is the name of the file to decrypt: ")
				filename := readline()
				decryptFile(filename, key)

			}

		}
	}
}
