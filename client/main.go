package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/levigross/grequests"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func main() {
	//get()
	//post()
	getIpfsSwarmPeers()
}

//curl -X POST "http://127.0.0.1:5001/api/v0/swarm/peers?verbose=<value>&streams=<value>&latency=<value>&direction=<value>"
func getIpfsSwarmPeers()  {
	// {"user": "manu", "password": "123"}
	option := SdAuthRequestOption()
	option.RequestTimeout = 2 * time.Second
	resp, err := grequests.Post("http://127.0.0.1:5001/api/v0/swarm/peers", option)
	if err != nil {
		fmt.Printf("%+\n", err.Error())
		return
	}
	fmt.Printf("%+v\n", resp.String())
}

func get()  {
	//http://127.0.0.1:3004/post?user=manu&password=123
	option := SdAuthRequestOption()
	option.Params = map[string]string{
		"user":     "manu",
		"password": "123",
	}
	option.RequestTimeout = 2 * time.Second
	resp, err := grequests.Get("http://127.0.0.1:3004/post", option)
	if err != nil {
		fmt.Printf("%+\n", err.Error())
		return
	}
	fmt.Printf("%+v\n", resp.String())
}
func post()  {
	// {"user": "manu", "password": "123"}
	option := SdAuthRequestOption()
	option.JSON = map[string]interface{}{
		"user":     "manu",
		"password": "123",
	}
	option.RequestTimeout = 2 * time.Second
	resp, err := grequests.Post("http://127.0.0.1:3004/post", option)
	if err != nil {
		fmt.Printf("%+v\n", err.Error())
		return
	}
	fmt.Printf("%+v\n", resp.String())
}


var (
	AK = "017194e9718f07feefc4b03422d8be5df654bafc623251480f7d760d1209b4ca39"
	SK = "02595d553697305c7670dfd92628e5ff68080335265edf804aea4e6e8df5112464"
)

func formatURLPath(in string) string {
	in = strings.TrimSpace(in)
	if strings.HasSuffix(in, "/") {
		return in[:len(in)-1]
	}
	return in
}

func sdBeforeRequestFunc(req *http.Request) error {
	beforeRequestFuncWithKey(req, AK, SK)
	return nil
}
func SdAuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      sdBeforeRequestFunc,
	}
	return option
}

func beforeRequestFuncWithKey(req *http.Request, ak, sk string) error {
	var (
		timestamp   = fmt.Sprintf(`%d`, time.Now().Unix())
		err         error
		requestBody []byte
	)

	if req.Body != nil {
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		//Reset after reading
		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))
	} else {
		requestBody = []byte{}
	}
	sign := generateSign(req.Method, formatURLPath(req.URL.Path), req.URL.RawQuery, ak, timestamp, sk, requestBody)
	req.Header.Add("AccessKey", ak)
	req.Header.Add("Signature", sign)
	req.Header.Add("TimeStamp", timestamp)
	return nil
}
func sha256byteArr(in []byte) string {
	fmt.Println(string(in))
	if in == nil || len(in) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(in)
	return hex.EncodeToString(h.Sum(nil))
}

func generateSign(method, url, query, ak, timestamp, sk string, requestBody []byte) string {
	fmt.Println(sha256byteArr(requestBody))
	fmt.Printf("before sign: %+v\n",fmt.Sprintf(`%s\n%s\n%s\n%s\n%s\n%s`, method, url, query, ak, timestamp, sha256byteArr(requestBody)))
	sign:=hmacSha256(fmt.Sprintf(`%s\n%s\n%s\n%s\n%s\n%s`, method, url, query, ak, timestamp, sha256byteArr(requestBody)), sk)
	fmt.Printf("sign: %+v\n", sign)
	return sign
}

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
