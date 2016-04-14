package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha512"
	"hash"
	"crypto/hmac"
	"crypto/sha256"
	//"crypto/subtle"
)

// type dataMap map[string]interface{}

func main()  {
	type Profile struct {
		UUID          string
		UpdatedAt     int64
		CreatedAt     int64
		LastUpdatedBy string
		ProfileName   string
		PasswordHint  string
		Iterations    int
		Salt          []byte
		OverviewKey   []byte
		MasterKey     []byte

		masterEncKey   []byte
		masterMacKey   []byte
		overviewEncKey []byte
		overviewMacKey []byte
	}

	var idx int
	var p *Profile
	var profile_json []byte

	profile_file, err := ioutil.ReadFile("/Users/eherot/Dropbox/Apps/1Password/1Password.opvault/default/profile.js")
	if err != nil {
		log.Fatal(err)
	}
	idx = bytes.IndexByte(profile_file, '{')
	if idx < 0 {
		log.Fatal("invalid profile data")
	}
	profile_json = profile_file[idx:]

	idx = bytes.LastIndexByte(profile_json, '}')
	if idx < 0 {
		log.Fatal("invalid profie data")
	}
	profile_json = profile_json[:idx+1]

	// fmt.Printf("JSON Blob: %+s\n", profile_json)
	err = json.Unmarshal(profile_json, &p)
	if err != nil {
		log.Fatal(err)
	}

	var (
		pwd           = os.Getenv("MASTER_PW")
		dk            = pbkdf2.Key([]byte(pwd), p.Salt, p.Iterations, 64, sha512.New)
		encKey = dk[:32] // First 32 chars
		macKey = dk[32:] // Last 32 chars
		src = p.MasterKey
		//macBuf  [32]byte
		macSrc  []byte
		mac     hash.Hash
		//dataLen uint64
		//dataIV  [16]byte
	)

	fmt.Printf("dk: %s\n", dk)
	fmt.Printf("macKey: %v\n", base64.StdEncoding.EncodeToString(macKey))
	fmt.Printf("encKey: %s\n", base64.StdEncoding.EncodeToString(encKey))

	{ // verify mac
		if len(src) < 32 {
			log.Fatal("invalid opdata signature length")
		}

		fmt.Printf("src: %s\n", src)

		macSrc = src[len(src)-32:] // Last 32 characters
		fmt.Printf("macSrc: %s\n", macSrc)
		src = src[:len(src)-32] // All but last 32 characters
		mac = hmac.New(sha256.New, macKey)
		mac.Write(src)
		//mac.Sum(macBuf[:0])
		macBuf := mac.Sum(nil)
		fmt.Printf("macBuf-base64: %s\n", base64.StdEncoding.EncodeToString(macBuf))
		fmt.Printf("macBuf: %s\n", macBuf)
		if ! hmac.Equal(macBuf, macSrc) {
			log.Fatal("invalid opdata signature")
		}
		//if subtle.ConstantTimeCompare(macBuf[:], macSrc) != 1 {
		//	log.Fatal("invalid opdata signature")
		//}
	}

	// fmt.Printf("Master Key: %s\n", profile.MasterKey)
	// fmt.Println(profile_file)
	ciphertext, _ := base64.StdEncoding.DecodeString("b3BkYXRhMDEAAQAAAAAAALGPJo9cVJZrkN1mlMObpNLt1hpmZ/jOktIW1oqD68CkQ9J+OeUHl0r/ZnhEV3EDRwaYMYlnLGKsijtuhCkJcXhXxw6MdhWod72uir7576dbcJhZSHVx7I1WEmXMNjlv1dCfkKLN0HUKLYgGM24mCA4S9KY7rXSpoN3gic/zTS54K22GSYCYnsPq4o7aR25F8F6jQEc9LaIjIMwddHpbWA/fX3LzpUdx9M0Vff6tOrmiBB8Bn70o22Hag1hmU5SfbAbAmSgd9NoUuUHW99pM8kazkVV5Byc+fZyXEIxjHIznB5jUwMlw+AakmR5OYEuFkrKV7xw6udzOV2lLDbm9qh4HWoC55ZsYKr63V1YRc2GBB7Gtg3ulEw3pKf/mqi9b0OKlAb1awADoRdTClY1qs13vvtXShH2pGL1G4tZpaYPz")

	data, _ := ciphertext[:len(ciphertext)-32], ciphertext[len(ciphertext)-32:]
	// iv, paddedData := data[16:32], data[32:]

	testtext := "abcdefghij"
  fmt.Println("\n" + testtext[3:5])

	// fmt.Println("data: " + data)
	// fmt.Println("mac: " + mac)
	// fmt.Println("iv: " + iv)
	// fmt.Println("paddedData: " + paddedData)

	if bytes.Equal(data[:8], []byte{'o', 'p', 'd', 'a', 't', 'a', '0', '1'}) {
		fmt.Println("opdata detected")
	}
}

// func (d dataMap) getBytes(key string) []byte {
//   val, _ := d[key].(string)
//   if val == "" {
//     return nil
//   }

//   data, _ := base64.StdEncoding.DecodeString(val)
//   return data
// }
