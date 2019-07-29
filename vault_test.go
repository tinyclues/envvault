package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultClient_GetSecret_returns_secret_at_value(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "myToken", r.Header.Get("X-Vault-Token"))
		assert.Equal(t, "/v1/path1", r.URL.Path)
		fmt.Fprint(w, `{"data": {"value": "this is the secret"}}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1")
	// Then
	assert.NoError(t, err)
	assert.Equal(t, "this is the secret", secret)
}

func TestVaultClient_GetSecret_returns_secret_at_key(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "myToken", r.Header.Get("X-Vault-Token"))
		assert.Equal(t, "/v1/path1", r.URL.Path)
		fmt.Fprint(w, `{"data": {"key1": "this is the secret"}}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1:key1")
	// Then
	assert.NoError(t, err)
	assert.Equal(t, "this is the secret", secret)
}

func TestVaultClient_GetSecret_returns_err_if_secret_is_empty(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data": {"value": ""}}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1")
	// Then
	assert.Empty(t, secret)
	assert.EqualError(t, err, "empty secret at path 'path1'")
}

func TestVaultClient_GetSecret_returns_err_if_json_cannot_be_parsed(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `this is not a valid json {}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1")
	// Then
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "cannot parse Vault response body")
}

func TestVaultClient_GetSecret_returns_err_if_not_200(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1")
	// Then
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "cannot get secret 'path1' from Vault")
}

func TestVaultClient_GetSecret_returns_err_if_request_fails(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	httpClient := server.Client()
	server.Close() // kill the server
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.GetSecret("myToken", "var1", "path1")
	// Then
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "cannot get secret 'path1' from Vault")
}

func TestVaultClient_Authenticate_returns_token(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/auth/approle/login", r.URL.Path)
		body, _ := ioutil.ReadAll(r.Body)
		assert.Equal(t, `payload`, string(body))
		fmt.Fprint(w, `{"auth": {"client_token": "this is the token"}}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.Authenticate([]byte("payload"))
	// Then
	assert.NoError(t, err)
	assert.Equal(t, "this is the token", secret)
}

func TestVaultClient_Authenticate_returns_err_if_token_is_empty(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"foo": "bar"}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.Authenticate([]byte("payload"))
	// Then
	assert.Empty(t, secret)
	assert.EqualError(t, err, `cannot find token in Vault response: body={"foo": "bar"}`)
}

func TestVaultClient_Authenticate_returns_err_if_json_cannot_be_parsed(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `this is not a valid json {}`)
	}))
	defer server.Close()

	httpClient := server.Client()
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.Authenticate([]byte("payload"))
	// Then
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "cannot parse Vault response body")
}

func TestVaultClient_Authenticate_returns_err_if_request_fails(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	httpClient := server.Client()
	server.Close() // kill the server
	client := NewVaultClient(httpClient, server.URL)
	// When
	secret, err := client.Authenticate([]byte("payload"))
	// Then
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "cannot do POST to get token from Vault")
}

type FakeS3Downloader struct {
	mock.Mock
	downloadResult string
}

func (d FakeS3Downloader) Download(w io.WriterAt, input *s3.GetObjectInput, options ...func(*s3manager.Downloader)) (int64, error) {
	w.WriteAt([]byte(d.downloadResult), 0)
	args := d.Called(w, input, options)
	return int64(args.Int(0)), args.Error(1)
}

func (d FakeS3Downloader) DownloadWithContext(ctx aws.Context, w io.WriterAt, input *s3.GetObjectInput, options ...func(*s3manager.Downloader)) (n int64, err error) {
	args := d.Called(ctx, w, input, options)
	return int64(args.Int(0)), args.Error(1)
}

func TestAppRoleDownloader_GetAuthPayload_returns_auth_payload_with_good_keys(t *testing.T) {
	// Given
	s3Downloader := &FakeS3Downloader{downloadResult: `{"role_id": "myRoleId", "secret_role_id": "mySecretId"}`}
	s3Downloader.On(
		"Download",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(123, nil)

	downloader := NewAppRoleDownloader(s3Downloader)
	// When
	authPayload, err := downloader.GetAuthPayload("myBucket", "myKey")
	// Then
	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"role_id": "myRoleId", "secret_id": "mySecretId"}`), authPayload)
}

func TestAppRoleDownloader_GetAuthPayload_returns_auth_payload(t *testing.T) {
	// Given
	s3Downloader := &FakeS3Downloader{downloadResult: `{"role_id": "myRoleId", "secret_id": "mySecretId"}`}
	s3Downloader.On(
		"Download",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(123, nil)

	downloader := NewAppRoleDownloader(s3Downloader)
	// When
	authPayload, err := downloader.GetAuthPayload("myBucket", "myKey")
	// Then
	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"role_id": "myRoleId", "secret_id": "mySecretId"}`), authPayload)
}

func TestAppRoleDownloader_GetAuthPayload_returns_err_if_download_fails(t *testing.T) {
	// Given
	s3Downloader := &FakeS3Downloader{}
	s3Downloader.On(
		"Download",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(0, fmt.Errorf("whoops"))

	downloader := NewAppRoleDownloader(s3Downloader)
	// When
	authPayload, err := downloader.GetAuthPayload("myBucket", "myKey")
	// Then
	assert.Empty(t, authPayload)
	assert.Contains(t, err.Error(), "cannot download approle credentials file from S3: bucket=myBucket, key=myKey")
}

func TestAppRoleDownloader_GetAuthPayload_returns_err_if_parsing_fails(t *testing.T) {
	// Given
	s3Downloader := &FakeS3Downloader{downloadResult: `bad json with secret_role_id`}
	s3Downloader.On(
		"Download",
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(0, nil)

	downloader := NewAppRoleDownloader(s3Downloader)
	// When
	authPayload, err := downloader.GetAuthPayload("myBucket", "myKey")
	// Then
	assert.Empty(t, authPayload)
	assert.Contains(t, err.Error(), "cannot parse approle credentials")
}
