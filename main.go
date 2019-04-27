package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/gorilla/mux"
)

const (
	GithubAccessToken = "https://github.com/login/oauth/access_token"
)

var (
	Passphrase string
)

func init() {
	Passphrase = readPassphrase()
}

func checkErr(err error, msg string, v ...interface{}) {
	if err != nil {
		message := fmt.Sprintf(msg, v...)
		panic(fmt.Sprintf("%s: error: %s", message, err))
	}
}

func doExist(array []string, key string) bool {
	for _, a := range array {
		if a == key {
			return true
		}
	}
	return false
}

func makeRouter(
	methods []string,
	handler func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("%s", err)))
			}
		}()

		if !doExist(methods, r.Method) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Wrong Method %s, should use %s", r.Method, methods)))
			return
		}

		handler(w, r)
	}
}

func getArgument(r *http.Request, field string) string {
	v := r.FormValue(field)
	if v == "" {
		panic(fmt.Sprintf("can not get argument %s from request", field))
	}
	return v
}

func getCurrentDir() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	checkErr(err, "getCurrentDir filepath.Abs error. binary %s", os.Args[0])
	return dir
}

func readPassphrase() string {
	f := path.Join(getCurrentDir(), "passphrase")
	passphrase, err := ioutil.ReadFile(f)
	checkErr(err, "readPassphrase ioutil.ReadFile error. file %s", f)

	return string(passphrase)
}

func post(path string, data map[string]string) *simplejson.Json {
	form := url.Values{}
	for k, v := range data {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	checkErr(err, "post client.Do error")

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err, "post ioutil.ReadAll error")

	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("failed to post. status code: %d, body: %s", resp.StatusCode, body))
	}

	res, err := simplejson.NewJson(body)
	checkErr(err, "post simplejson.NewJson error. body %s", body)

	return res
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(text, passphrase string) string {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	checkErr(err, "encrypt cipher.NewGCM error")

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	checkErr(err, "encrypt io.ReadFull error")

	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(text), nil))
}

func decrypt(ciphertext, passphrase string) string {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	checkErr(err, "decrypt aes.NewCipher error")

	gcm, err := cipher.NewGCM(block)
	checkErr(err, "decrypt cipher.NewGCM error")

	nonceSize := gcm.NonceSize()
	data, err := hex.DecodeString(ciphertext)
	checkErr(err, "decrypt hex.DecodeString error")

	nonce, cipher := data[:nonceSize], data[nonceSize:]
	text, err := gcm.Open(nil, nonce, cipher, nil)
	checkErr(err, "decrypt gcm.Open error")

	return string(text)
}

func okClient(w http.ResponseWriter, r *http.Request) {
 	w.Write([]byte("ok"))
}

func encodeSecretClient(w http.ResponseWriter, r *http.Request) {
	secret := getArgument(r, "client_secret")
	encoded := encodeSecret(secret)
 	w.Write([]byte(encoded))
}

func encodeSecret(secret string) string {
	return encrypt(secret, Passphrase)
}

func decodeSecretClient(w http.ResponseWriter, r *http.Request) {
	encodedSecret := getArgument(r, "client_encoded_secret")
	secret := decodeSecret(encodedSecret)
 	w.Write([]byte(secret))
}

func decodeSecret(encodedSecret string) string {
	return decrypt(encodedSecret, Passphrase)
}

type MessageAccessToken struct {
	Code                string `json:"code"`
	ClientId            string `json:"client_id"`
	ClientEncodedSecret string `json:"client_encoded_secret"`
}

func getAccessTokenClient(w http.ResponseWriter, r *http.Request) {
	info := &simplejson.Json{}
	if r.Method == "POST" {
		b, err := ioutil.ReadAll(r.Body)
		checkErr(err, "can not read body from request")
		defer r.Body.Close()

		var msg MessageAccessToken
		err = json.Unmarshal(b, &msg)
		checkErr(err, "can not unmarshal body")

		clientSecret := decrypt(msg.ClientEncodedSecret, Passphrase)
		info = getAccessToken(msg.Code, msg.ClientId, clientSecret)
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers",
		"Origin, X-Requested-With, Content-Type, Accept, Authorization")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func getAccessToken(code, clientId, clientSecret string) *simplejson.Json {
	return post(GithubAccessToken, map[string]string{
		"code":          code,
		"client_id":     clientId,
		"client_secret": clientSecret,
	})
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/ok", makeRouter([]string{"GET"}, okClient))
	router.HandleFunc("/encoded_secret", makeRouter([]string{"POST"}, encodeSecretClient))
	router.HandleFunc("/secret", makeRouter([]string{"GET"}, decodeSecretClient))
	router.HandleFunc("/login/oauth/access_token", makeRouter([]string{"OPTIONS", "POST"}, getAccessTokenClient))

	err := http.ListenAndServe(":8000", router)
	if err != nil {
		fmt.Println("failed to ListenAndServe: ", err)
		os.Exit(1)
	}
}
