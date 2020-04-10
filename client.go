package dropbox

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client implements a Dropbox client. You may use the Files and Users
// clients directly if preferred, however Client exposes them both.
type Client struct {
	*Config
	Users   *Users
	Files   *Files
	Sharing *Sharing
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
	url := "https://api.dropboxapi.com/2" + path

	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	r, _, err := c.do(req)
	return r, err
}

// download style endpoint.
func (c *Client) download(path string, in interface{}, r io.Reader) (io.ReadCloser, int64, error) {
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

	if r != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	return c.do(req)
}

// perform the request.
func (c *Client) do(req *http.Request) (io.ReadCloser, int64, error) {
	var err error
	var res *http.Response
	error_retry_time := 0.5
request_loop:
	for error_retry_time < 300 {
		res, err = c.HTTPClient.Do(req)
		switch {
		case res.StatusCode == 429:
			sleep_time, conv_e := strconv.Atoi(res.Header.Get("Retry-After"))
			if conv_e != nil {
				sleep_time = 60
			}
			time.Sleep(time.Duration(sleep_time) * time.Second)
		case res.StatusCode >= 500: // Retry on 5xx
			time.Sleep(time.Duration(error_retry_time) * time.Second)
			error_retry_time *= 1.5
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
