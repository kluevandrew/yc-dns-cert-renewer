package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/go-acme/lego/lego"
	"github.com/spf13/viper"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	YandexFolderID    string
	YandexCredentials ycsdk.Credentials

	LeEmail      string
	LePrivateKey *ecdsa.PrivateKey
	LeDirectory  string

	K8SMode       string
	K8SConfigPath string

	Certificates Certificates

	ArchivePath string
}

func Load() (*Config, error) {
	viper.SetDefault("yc_account", "")
	viper.SetDefault("yc_folder_id", "")
	viper.SetDefault("le_email", "")
	viper.SetDefault("le_private_key", "")
	viper.SetDefault("le_directory", lego.LEDirectoryProduction)
	viper.SetDefault("k8s_mode", "in_cluster")
	viper.SetDefault("k8s_config_path", "")
	viper.SetDefault("archive_path", "./archive")
	viper.SetDefault("certificates_config_path", "/certificates.conf.yaml")

	viper.SetConfigFile(".env")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err.Error())
	}

	viper.AutomaticEnv()

	ycCreds, err := decodeYcCredentials(viper.GetString("yc_account"))
	if err != nil {
		return nil, err
	}

	lePrivate, err := decodePrivateKey(viper.GetString("le_private_key"))
	if err != nil {
		return nil, err
	}

	certificates, err := loadCertificatesConfig(viper.GetString("certificates_config_path"))
	if err != nil {
		return nil, err
	}

	appConfig := &Config{
		YandexFolderID:    viper.GetString("yc_folder_id"),
		YandexCredentials: ycCreds,
		LeEmail:           viper.GetString("le_email"),
		LePrivateKey:      lePrivate,
		LeDirectory:       viper.GetString("le_directory"),
		K8SMode:           viper.GetString("k8s_mode"),
		K8SConfigPath:     viper.GetString("k8s_config_path"),
		Certificates:      certificates,
		ArchivePath:       viper.GetString("archive_path"),
	}

	return appConfig, nil
}

func loadCertificatesConfig(filepath string) (Certificates, error) {
	certificates := make(Certificates, 0)

	yamlConfig, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlConfig, &certificates)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func decodeYcCredentials(ycAccountB64 string) (ycsdk.Credentials, error) {
	ycAccountJSON, err := base64.StdEncoding.DecodeString(ycAccountB64)
	if err != nil {
		return nil, err
	}

	key := &iamkey.Key{}

	err = json.Unmarshal(ycAccountJSON, key)
	if err != nil {
		return nil, err
	}

	return ycsdk.ServiceAccountKey(key)
}

func decodePrivateKey(pemEncodedB64 string) (*ecdsa.PrivateKey, error) {
	pemEncoded, err := base64.StdEncoding.DecodeString(pemEncodedB64)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemEncoded)

	return x509.ParseECPrivateKey(block.Bytes)
}
