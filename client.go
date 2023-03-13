package dropbox

import (
	"fmt"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
	"log"
	"sync"

	"golang.org/x/oauth2"
)

// Client implements a Dropbox client. You may use the Files and Users
// clients directly if preferred, however Client exposes them both.
type Client struct {
	*Config
	Users   *Users
	Files   *Files
	Sharing *Sharing

	Token     oauth2.Token
	TokenLock sync.Mutex
}

// New client.
func New(config *Config) *Client {
	c := &Client{Config: config}
	c.Users = &Users{c}
	c.Files = &Files{c}
	c.Sharing = &Sharing{c}
	return c
}

// call rpc style endpoint.
func (c *Client) call(path string, in interface{}) (io.ReadCloser, error) {

	var err error
	if c.AccessToken == "" && c.RefreshToken != "" {
		err = c.refreshToken()
		if err != nil {
			return nil, err
		}
	}

	url := "https://api.dropboxapi.com/2" + path

	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(body)
	req, err := http.NewRequest("POST", url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	r, _, err := c.do(req, reader)
	return r, err
}

// download style endpoint.
func (c *Client) download(path string, in interface{}, r io.ReadSeeker, contentLength int64) (io.ReadCloser, int64, error) {

	url := "https://content.dropboxapi.com/2" + path

	body, err := json.Marshal(in)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest("POST", url, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Dropbox-API-Arg", string(body))
        if contentLength != 0 {
            req.ContentLength = contentLength
        }
	if r != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	return c.do(req, r)
}

// perform the request.
func (c *Client) do(req *http.Request, seeker io.Seeker) (io.ReadCloser, int64, error) {
	var err error

	var res *http.Response
	error_retry_time := 0.5
request_loop:
	for error_retry_time < 300 {
		if res != nil && err == nil {
			// be sure to close the response before retrying
			ioutil.ReadAll(res.Body)
			res.Body.Close()
		}
		res, err = c.HTTPClient.Do(req)
		if err != nil {
			log.Printf("[DROPBOX_RETRY] %v; retrying after %.2f seconds", err, error_retry_time)
			time.Sleep(time.Duration(error_retry_time) * time.Second)
			error_retry_time *= 1.5
			if seeker != nil {
				seeker.Seek(0, io.SeekStart)
			}
			continue
		}

		switch {
		case res.StatusCode == 429:
			sleep_time, conv_e := strconv.Atoi(res.Header.Get("Retry-After"))
			if conv_e != nil {
				sleep_time = 60
			}
			log.Printf("[DROPBOX_RETRY] %s %s returned %d; retrying after %d seconds", req.Method, req.URL, res.StatusCode, sleep_time)
			time.Sleep(time.Duration(sleep_time) * time.Second)
			if seeker != nil {
				seeker.Seek(0, io.SeekStart)
			}
		case res.StatusCode == 401:
			log.Printf("[DROPBOX_RETRY] %s %s returned %d; refreshing access token", req.Method, req.URL, res.StatusCode)
			err = c.refreshToken()
			req.Header.Set("Authorization", "Bearer "+c.AccessToken)
			if err != nil {
				log.Printf("[DROPBOX_RETRY] %s returned an error: %v", c.RefreshURL, err)
				time.Sleep(time.Duration(error_retry_time) * time.Second)
				error_retry_time *= 1.5
			}
			if seeker != nil {
				seeker.Seek(0, io.SeekStart)
			}
		case res.StatusCode >= 500: // Retry on 5xx
			log.Printf("[DROPBOX_RETRY] %s %s returned %d; retrying after %.2f seconds", req.Method, req.URL, res.StatusCode, error_retry_time)
			time.Sleep(time.Duration(error_retry_time) * time.Second)
			error_retry_time *= 1.5
			if seeker != nil {
				seeker.Seek(0, io.SeekStart)
			}
		default:
			break request_loop
		}
	}
	if err != nil {
		return nil, 0, err
	}

	if res.StatusCode < 400 {
		return res.Body, res.ContentLength, err
	}

	defer res.Body.Close()

	e := &Error{
		Status:     http.StatusText(res.StatusCode),
		StatusCode: res.StatusCode,
	}

	kind := res.Header.Get("Content-Type")

	if strings.Contains(kind, "text/plain") {
		if b, err := ioutil.ReadAll(res.Body); err == nil {
			e.Summary = string(b)
			return nil, 0, e
		} else {
			return nil, 0, err
		}
	}

	if err := json.NewDecoder(res.Body).Decode(e); err != nil {
		return nil, 0, err
	}
	return nil, 0, e
}

func (client *Client) refreshToken() (err error) {
	if client.RefreshToken == "" {
		return fmt.Errorf("No refresh token provided")
	}

	client.TokenLock.Lock()
	defer client.TokenLock.Unlock()

	if client.Token.Valid() {
		return nil
	}

	client.Token.AccessToken = ""
	client.Token.RefreshToken = client.RefreshToken
	body, err := json.Marshal(client.Token)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", client.RefreshURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to refresh the access token: %v", err)
	}

    defer response.Body.Close()
	if err = json.NewDecoder(response.Body).Decode(&client.Token); err != nil {
		return err
	}

	if client.Token.AccessToken == "" {
		return fmt.Errorf("No access token returned")
	}
	
	client.AccessToken = client.Token.AccessToken

	return nil
}
