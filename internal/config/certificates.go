package config

type Certificates []Certificate

type Certificate struct {
	Domains    []string `yaml:"domains"`
	Namespaces []string `yaml:"namespaces"`
	SecretName string   `yaml:"secretName"`
}
