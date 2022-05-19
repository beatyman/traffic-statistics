package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Login struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func main() {
	router := gin.Default()
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
	router.Use(gin.Recovery())
	router.Use(Cors())
	router.Use(AKSKAuth())
	// post  {"user": "manu", "password": "123"}
	router.POST("/post", func(c *gin.Context) {
		var json Login
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if json.User != "manu" || json.Password != "123" {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": fmt.Sprintf(" user: %s are logged in ,password: %s", json.User, json.Password)})
	})
	// post?user=manu&password=123
	router.GET("/post", func(c *gin.Context) {
		user := c.Query("user")
		password := c.Query("password") // shortcut for c.Request.URL.Query().Get("lastname")
		c.String(http.StatusOK, " user: %s are logged in ,password: %s", user, password)
	})

	router.Run(":3004")
}
/*
map[
Accept-Encoding:[gzip]

Accesskey:[017194e9718f07feefc4b03422d8be5df654bafc623251480f7d760d1209b4ca39]
Content-Length:[65]
Content-Type:[application/json]
Signature:[2e18b8aa4520a163996ab22248ff4193621a9b759752b8d00b7e873b4f7870ea]
Timestamp:[1652774168]

User-Agent:[GRequests/0.10]]

[GIN] 2022/05/17 - 15:56:08 | 200 |            0s |       127.0.0.1 | POST     "/post"

*/

var (
	AK = "017194e9718f07feefc4b03422d8be5df654bafc623251480f7d760d1209b4ca39"
	SK = "02595d553697305c7670dfd92628e5ff68080335265edf804aea4e6e8df5112464"
)

func getSecKec(ak string) string {
	if strings.Compare(AK, ak) == 0 {
		return SK
	}
	return ""
}
func AKSKAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			ak, sk, sign, timeStamp, serverSign string
			iTime, timeDiff                     int64
			err                                 error
			requestBody                         []byte
		)

		ak = c.Request.Header.Get("AccessKey")
		sign = c.Request.Header.Get("Signature")
		timeStamp = c.Request.Header.Get("TimeStamp")
		if ak == "" || sign == "" || timeStamp == "" {
			abort(c, "header missed: AccessKey|Signature|TimeStamp")
			return
		}
		log.Infof("client:  AccessKey: %+v",ak)
		log.Infof("client:  Signature: %+v",sign)
		log.Infof("client:  TimeStamp: %+v",timeStamp)
		//check time
		iTime, err = strconv.ParseInt(timeStamp, 10, 64)
		if err != nil {
			abort(c, fmt.Sprintf(`TimeStamp Error %s`, err.Error()))
			return
		}
		timeDiff = time.Now().Unix() - iTime
		if timeDiff >= 60 || timeDiff <= -60 {
			abort(c, "timestamp error")
			return
		}
		//check signature
		sk = getSecKec(ak)
		if sk == "" {
			abort(c, "User not exist")
			return
		}
		requestBody, err = ioutil.ReadAll(c.Request.Body)
		if err != nil {
			abort(c, err.Error())
			return
		}
		c.Request.Body.Close()
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))

		serverSign = generateSign(c.Request.Method, formatURLPath(c.Request.URL.Path), c.Request.URL.RawQuery, ak, timeStamp, sk, requestBody)
		log.Infof("server Signature: %+v ",serverSign)
		if serverSign != sign {
			abort(c, "signature error")
			return
		}
		c.Next()
		return
	}
}
func formatURLPath(in string) string {
	in = strings.TrimSpace(in)
	if strings.HasSuffix(in, "/") {
		return in[:len(in)-1]
	}
	return in
}

func sha256byteArr(in []byte) string {
	if in == nil || len(in) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(in)
	return hex.EncodeToString(h.Sum(nil))
}

func generateSign(method, url, query, ak, timestamp, sk string, requestBody []byte) string {
	return hmacSha256(fmt.Sprintf(`%s\n%s\n%s\n%s\n%s\n%s`, method, url, query, ak, timestamp, sha256byteArr(requestBody)), sk)
}

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func abort(c *gin.Context, reason string) {
	c.Abort()
	CreateResponse(c, AuthFailedErrorCode, reason)
	return
}

const (
	SuccessCode = iota
	AuthFailedErrorCode
	DuplicateFieldErrorCode
	DBOperateErrorCode
	RedisOperateErrorCode
	ParamInvalidErrorCode
	DBNoRowAffectedErrorCode
	TemporarilyUnavailable
	ErrorIDLen
	ErrorID
	UnknownErrorCode
	TimeOutErrorCode
	RemoteAllFailedErrorCode
	ProjectIDRespect
	SomeFieldIsNull
)

var ErrorDescriptions = map[int]string{
	SuccessCode:              "success",
	AuthFailedErrorCode:      "auth failed",
	DuplicateFieldErrorCode:  "duplicate field",
	DBOperateErrorCode:       "db operate error",
	RedisOperateErrorCode:    "redis operate error",
	ParamInvalidErrorCode:    "param invalid",
	DBNoRowAffectedErrorCode: "db no row affected",
	TemporarilyUnavailable:   "resource temporarily unavailable",
	ErrorIDLen:               "ID MAX LEN IS 1-15",
	ErrorID:                  "ID ONLY SYUUPRT 'A-Z/a-z/0-9/-/_'",
	UnknownErrorCode:         "unknown error",
	ProjectIDRespect:         "PROJECT ID REPECT",
	SomeFieldIsNull:          "SOME FIELD IS NUL",
	TimeOutErrorCode:         "get result timeout",
	RemoteAllFailedErrorCode: "all remote instance failed",
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

func (response *Response) SetError(code int) {
	response.Code = code

	if msg, ok := ErrorDescriptions[code]; ok {
		response.Message = msg
	}
}

func CreateResponse(c *gin.Context, code int, data interface{}) {
	var response Response

	response.SetError(code)
	response.Data = data
	c.JSON(
		http.StatusOK,
		response,
	)
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*")  // 可将将 * 替换为指定的域名
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization,AccessKey,Signature,TimeStamp")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		c.Next()
	}
}