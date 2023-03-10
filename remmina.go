//Decrypts obfuscated passwords by Remmina - The GTK+ Remote Desktop Client
//written by Michael Cochez

// written by Robin He (https://github.com/gzhechu)

package main

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/ini.v1"
)

var secretFile = ".config/remmina/remmina.pref"
var passwdFolder = ".local/share/remmina"

//set the variables here

var base64secret = "vCdMntBxnjHS5gvIgerSxewMv0bmYVj/Gu2N5dI2q44="
var base64password = "fPwbyUMhdPpCWEO2YzJgGQ=="

//The secret is used for encrypting the passwords. This can typically be found from ~/.remmina/remmina.pref on the line containing 'secret='.
//"The encrypted password used for the connection. This can typically be found from /.remmina/dddddddddddd.remmina " on the line containing 'password='.
//Copy everything after the '=' sign. Also include final '=' signs if they happen to be there.

func getSecret(fn string) (err error, secret string) {
	inifile, err := ini.Load(fn)
	if err != nil {
		return
	}
	secret = inifile.Section("remmina_pref").Key("secret").String()
	return
}

func getSessionPwd(fn string) (err error, cfgs map[string]string) {
	cfgs = make(map[string]string)
	var files []string
	err = filepath.Walk(fn, func(path string, info os.FileInfo, err error) error {
		ext1 := filepath.Ext(path)
		if ext1 == ".remmina" {
			files = append(files, path)
		}
		return nil
	})

	for _, f := range files {
		inifile, err := ini.Load(f)
		if err != nil {
			log.Println(err)
		}
		name := inifile.Section("remmina").Key("name").String()
		passwd := inifile.Section("remmina").Key("password").String()
		cfgs[name] = passwd
	}

	return
}

//returns a function which can be used for decrypting passwords
func makeRemminaDecrypter(base64secret string) func(string) string {
	//decode the secret
	secret, err := base64.StdEncoding.DecodeString(base64secret)
	if err != nil {
		log.Fatal("Base 64 decoding failed:", err)
	}
	if len(secret) != 32 {
		log.Fatal("the secret is not 32 bytes long")
	}
	//the key is the 24 first bits of the secret
	key := secret[:24]
	//3DES cipher
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Fatal("Failed creating the 3Des cipher block", err)
	}
	//the rest of the secret is the iv
	iv := secret[24:]
	decrypter := cipher.NewCBCDecrypter(block, iv)

	return func(encodedEncryptedPassword string) string {
		encryptedPassword, err := base64.StdEncoding.DecodeString(encodedEncryptedPassword)
		if err != nil {
			log.Fatal("Base 64 decoding failed:", err)
		}
		//in place decryption
		decrypter.CryptBlocks(encryptedPassword, encryptedPassword)
		return string(encryptedPassword)
	}
}

func main() {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	filepath := fmt.Sprintf("%s/%s", dirname, secretFile)
	err, base64secret := getSecret(filepath)
	if err != nil {
		log.Fatalf("read secret file error: %v\n\n", err)
	}
	log.Printf("secret: %s", base64secret)

	filepath = fmt.Sprintf("%s/%s", dirname, passwdFolder)
	getSessionPwd(filepath)

	filepath = fmt.Sprintf("%s/%s", dirname, passwdFolder)
	err, cfgs := getSessionPwd(filepath)
	if err != nil {
		log.Fatalf("read session file error: %v\n\n", err)
	}

	for k, v := range cfgs {
		decrypter := makeRemminaDecrypter(base64secret)
		// log.Println(k, v)
		if len(v) > 0 {
			log.Printf("name: %s, passwd: %s\n", k, decrypter(v))
		} else {
			log.Printf("name: %s, no stored passwd\n", k)
		}
	}

}
