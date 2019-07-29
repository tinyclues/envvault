package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type VaultClient struct {
	httpClient *http.Client
	baseUrl    string
	secretCache map[string]map[string]string
}

func NewVaultClient(httpClient *http.Client, baseUrl string) *VaultClient {
	return &VaultClient{
		httpClient: httpClient,
		baseUrl:    baseUrl,
		secretCache: make(map[string]map[string]string),
	}
}

func (c *VaultClient) Authenticate(body []byte) (string, error) {
	log.Printf("[INFO] Authenticating to Vault at %v", c.baseUrl)

	authUrl := c.baseUrl + "/v1/auth/approle/login"
	resp, err := c.httpClient.Post(authUrl, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", errors.Wrapf(err, "cannot do POST to get token from Vault: url=%v", authUrl)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "cannot read Vault response body")
	}

	var tokenResponse struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	err = json.Unmarshal(respBody, &tokenResponse)
	if err != nil {
		return "", errors.Wrapf(err, "cannot parse Vault response body: body=%v", string(respBody))
	}
	if tokenResponse.Auth.ClientToken == "" {
		return "", fmt.Errorf("cannot find token in Vault response: body=%v", string(respBody))
	}

	return tokenResponse.Auth.ClientToken, nil
}

func (c *VaultClient) GetSecret(token string, name string, secretPath string) (string, error) {
	log.Printf("[INFO] Getting secret %v at %v", name, secretPath)

	elements := strings.SplitN(secretPath, ":", 2)
	path := elements[0]
	var key string
	if len(elements) == 2 {
		key = elements[1]
	} else {
		key = "value"
	}

	_, exists := c.secretCache[path]
	if !exists {
		url := c.baseUrl + "/v1/" + path

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Add("X-Vault-Token", token)

		response, err := c.httpClient.Do(req)
		if err != nil {
			return "", errors.Wrapf(err, "cannot get secret '%v' from Vault at %v", secretPath, c.baseUrl)
		}
		if response.StatusCode/100 != 2 {
			return "", fmt.Errorf("cannot get secret '%v' from Vault at %v: %v", secretPath, c.baseUrl, response.Status)
		}

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", errors.Wrap(err, "cannot read Vault response body")
		}

		var secretResponse struct {
			Data map[string]string `json:"data"`
		}

		err = json.Unmarshal(body, &secretResponse)
		if err != nil {
			return "", errors.Wrapf(err, "cannot parse Vault response body: secret=%v, body=%v, err=%v", secretPath, string(body))
		}

		c.secretCache[path] = secretResponse.Data
	}

	secretData, _ := c.secretCache[path]
	secret, exists := secretData[key]
	if !exists {
		return "", fmt.Errorf("cannot find key '%v' in json of path '%v'", key, path)
	}

	if secret == "" {
		return "", fmt.Errorf("empty secret at path '%v'", secretPath)
	}

	return secret, nil
}

type AppRoleDownloader struct {
	downloader s3manageriface.DownloaderAPI
}

func NewAppRoleDownloader(downloader s3manageriface.DownloaderAPI) *AppRoleDownloader {
	return &AppRoleDownloader{
		downloader: downloader,
	}
}

// NOTE: this function we should not have to deserialize JSON. We should simply return the content of the file on S3.
// but for the moment, the keys in the JSON are not the same as in the Vault authentication request.
func (d *AppRoleDownloader) GetAuthPayload(bucket string, key string) ([]byte, error) {
	log.Printf("[INFO] Downloading approle credentials from S3: bucket=%v, key=%v", bucket, key)

	buffer := aws.NewWriteAtBuffer(nil)
	_, err := d.downloader.Download(buffer, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "cannot download approle credentials file from S3: bucket=%v, key=%v", bucket, key)
	}
	rawPayload := buffer.Bytes()

	// Compatibility with json containing "secret_role_id"
	if strings.Contains(string(rawPayload), "secret_role_id") {
		log.Println(`[WARN] Old version of app role detected (it contains "secret_role_id" key)`)

		var appRole struct {
			RoleId       string `json:"role_id"`
			SecretRoleId string `json:"secret_role_id"`
		}
		err = json.Unmarshal(rawPayload, &appRole)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot parse approle credentials")
		}
		authPayload := fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, appRole.RoleId, appRole.SecretRoleId)
		return []byte(authPayload), nil
	}

	return rawPayload, nil
}
