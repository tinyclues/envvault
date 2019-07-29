package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"log"
	"net/http"
	"os"
	"time"
)

func getEnv(key string) string {
	value, found := os.LookupEnv(key)
	if found == false {
		log.Fatalf("environment variable %v not found", key)
	}
	return value
}

func main() {

	vaultEndpoint := getEnv("VAULT_ENDPOINT")
	appRoleBucket := getEnv("VAULT_BUCKET")
	appRoleKey := getEnv("VAULT_KEY")

	config := &Config{
		VaultBaseUrl:  vaultEndpoint,
		AwsRegion:     "eu-west-1",
		AppRoleBucket: appRoleBucket,
		AppRoleKey:    appRoleKey,
	}

	envvault := NewEnvVault(config)
	err := envvault.Run()
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(0)
}

type Config struct {
	VaultBaseUrl  string
	AwsRegion     string
	AppRoleBucket string
	AppRoleKey    string
}

type EnvVault struct {
	vaultClient *VaultClient
	authPayload []byte
}

func NewEnvVault(config *Config) *EnvVault {
	awsSession := session.Must(session.NewSession(aws.NewConfig().WithRegion(config.AwsRegion)))

	s3Downloader := s3manager.NewDownloader(awsSession)
	httpClient := &http.Client{
		Timeout: time.Second * 60,
	}
	appRoleDownloader := NewAppRoleDownloader(s3Downloader)
	authPayload, err := appRoleDownloader.GetAuthPayload(config.AppRoleBucket, config.AppRoleKey)
	if err != nil {
		log.Fatal(err)
	}

	vaultClient := NewVaultClient(httpClient, config.VaultBaseUrl)

	return &EnvVault{
		vaultClient: vaultClient,
		authPayload: authPayload,
	}
}

func (e EnvVault) Run() error {
	vaultToken, err := e.vaultClient.Authenticate(e.authPayload)
	if err != nil {
		return err
	}

	env := NewOsEnvironment()
	envWithPaths := GetEnvVarsWithPaths(env)
	envWithSecrets := NewEmptyEnvVars()
	for name, path := range envWithPaths {
		secret, err := e.vaultClient.GetSecret(vaultToken, name, path)
		if err != nil {
			return err
		}
		envWithSecrets[name] = secret
	}

	// Export of the poor
	// Note, instead of printing envs, we could launch a process with exec.Command
	// But if we do that we need to manage the subprocess lifecycle (envs, signals...)
	for _, val := range envWithSecrets.ExportStrings() {
		fmt.Println(val)
	}

	return err
}
