package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

func main() {
	cmd.RunWebhookServer("cubecloud",
		&cubeCloudDNSSolver{},
	)
}

// cubeCloudDNSSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type cubeCloudDNSSolver struct {
	cloudRouterApiDomain string
	cloudRouterApiToken  string
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *cubeCloudDNSSolver) Name() string {
	return "cube-cloud-dns-01-solver"
}

func (c *cubeCloudDNSSolver) MakeCloudRouterRequest(ch *v1alpha1.ChallengeRequest, action string) error {
	apiEndpoint := fmt.Sprintf("https://%s/_cloud-router/dns-challenge/%s", c.cloudRouterApiDomain, action)
	requestBody := map[string]string{
		"uid":          string(ch.UID),
		"action":       action,
		"key":          ch.Key,
		"resolvedFQDN": ch.ResolvedFQDN,
		"dnsName":      ch.DNSName,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error marshaling request body: %v", err)
	}

	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.cloudRouterApiToken))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to present DNS-01 challenge: received status code %v %s", resp.StatusCode, string(respBody))
	}

	fmt.Printf("TXT record presented for %v", ch.ResolvedFQDN)

	return nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *cubeCloudDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	return c.MakeCloudRouterRequest(ch, "present")
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *cubeCloudDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	return c.MakeCloudRouterRequest(ch, "cleanup")
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *cubeCloudDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	c.cloudRouterApiDomain = os.Getenv("CLOUD_ROUTER_API_DOMAIN")
	if c.cloudRouterApiDomain == "" {
		return fmt.Errorf("CLOUD_ROUTER_API_DOMAIN must be set")
	}
	c.cloudRouterApiToken = os.Getenv("CLOUD_ROUTER_API_TOKEN")
	if c.cloudRouterApiToken == "" {
		return fmt.Errorf("CLOUD_ROUTER_API_TOKEN must be set")
	}
	return nil
}
