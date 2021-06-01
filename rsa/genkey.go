package genkey

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	//"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	//"errors"
)

func GenerateKey() (string, error) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return string(key), nil

}

func Hashcipher(cipher string) []byte {
	// Convert cipher string to byte slice
	messageBytes := bytes.NewBufferString(cipher)
	hash := sha512.New()
	hash.Write(messageBytes.Bytes())
	digest := hash.Sum(nil)

	// Convert the hashed cipher to a base64 encoded string
	//var base64EncodedCipherHash = base64.URLEncoding.EncodeToString(digest)

	return digest
}

func PrivateandPublic() {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create("private.pem")
	if err != nil {
		fmt.Printf("error when create private.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		os.Exit(1)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}

func SDigest(message []byte) ([]byte, error) {
	// read keys from file
	privateKeyFile, err := os.Open("private.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Private Key : ", privateKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), message)
	var base64EncodedSign = hex.EncodeToString(signature)
	fmt.Println("Signmessage : ", base64EncodedSign)
	return signature, nil
}
func VerifyDG() error {
	file, err := os.Open("public.pem")
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem decryption
	block, _ := pem.Decode(buf)
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey := publicInterface.(*rsa.PublicKey)
	// metadata hash encryption
	hashtext, err := ioutil.ReadFile("hashtext.txt")
	//hashtexts :=hex.EncodeToString(hashtext)
	//fmt.Println(hashtexts)
	signedtext, err := ioutil.ReadFile("signedtext.txt")
	// signedtexts :=hex.EncodeToString(signedtext)
	//fmt.Println(signedtexts)

	//Verify the signature
	fmt.Println("Public:", publicKey)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.Hash(0), hashtext, signedtext)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}
