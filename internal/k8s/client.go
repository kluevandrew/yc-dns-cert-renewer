package k8s

import (
	"context"
	"errors"
	"fmt"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"yc-dns-cert-renewer/internal/config"
)

type Client struct {
	Mode       string
	ConfigPath string
	clientset  *kubernetes.Clientset
	namespaces v1.NamespaceInterface
}

func NewClient(cfg *config.Config) (*Client, error) {
	client := &Client{
		Mode:       cfg.K8SMode,
		ConfigPath: cfg.K8SConfigPath,
	}

	err := client.Configure()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Client) Configure() error {
	var cfg *rest.Config

	var err error

	switch c.Mode {
	case "in_cluster":
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	case "flags":
		cfg, err = clientcmd.BuildConfigFromFlags("", c.ConfigPath)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown k8s mode")
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	c.clientset = clientset
	c.namespaces = clientset.CoreV1().Namespaces()

	return err
}

func (c *Client) GetSecret(ctx context.Context, ns string, name string) (*apiv1.Secret, error) {
	secretsClient := c.clientset.CoreV1().Secrets(ns)
	return secretsClient.Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) CreateOrUpdateSecret(ctx context.Context, ns string, name string, certificate []byte, key []byte) error {
	secretsClient := c.clientset.CoreV1().Secrets(ns)

	secret := &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Data: map[string][]byte{
			"tls.crt": certificate,
			"tls.key": key,
		},
	}

	fmt.Println("Checking secret...")
	exists, err := secretsClient.Get(ctx, secret.ObjectMeta.Name, metav1.GetOptions{})
	if err == nil && exists != nil {
		fmt.Println("Updating secret...")

		exists.Data = secret.Data

		result, err := secretsClient.Update(ctx, exists, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

		fmt.Printf("Updated secret %q in ns %s.\n", result.GetObjectMeta().GetName(), ns)
	} else {
		fmt.Println("Creating secret...")

		result, err := secretsClient.Create(context.Background(), secret, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		fmt.Printf("Created secret %q in ns %s.\n", result.GetObjectMeta().GetName(), ns)
	}

	return nil
}
