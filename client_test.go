// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proofpoint

import (
	. "github.com/greenpau/go-proofpoint/internal/server"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	timerStartTime := time.Now()
	servicePrincipal := "8c5e8866-0062-4059-b2be-92707e4374da"
	principalSecret := "f982025ecbaa8c42bec8b19c98c3ea7126241c130274cd06ac4f15cbd3ec5313737a425f"

	// Create a client instance
	opts := make(map[string]interface{})
	opts["log_level"] = "debug"
	cli, err := NewClient(opts)
	if err != nil {
		t.Fatalf("failed initializing client: %s", err)
	}
	defer cli.Close()

	// Create web server instance
	endpoints := map[string][]*MockTestEndpoint{
		"/v2/siem/all": []*MockTestEndpoint{
			&MockTestEndpoint{
				RequestURI: "/v2/siem/all?format=json&sinceSeconds=7200",
				FileName:   "siem_all_format_json_since_seconds_7200.json",
			},
		},
	}

	basicAuth := map[string]string{
		"username": servicePrincipal,
		"password": principalSecret,
	}
	server, err := NewMockTestServer(cli.log, endpoints, basicAuth, true)
	if err != nil {
		t.Fatalf("Failed to initialize mock test server: %s", err)
	}
	defer server.Close()

	// Configure client
	cli.SetHost(server.NonTLS.Hostname)
	cli.SetPort(server.NonTLS.Port)
	cli.SetProtocol(server.NonTLS.Protocol)
	cli.SetServicePrincipal(servicePrincipal)
	cli.SetPrincipalSecret(principalSecret)
	if err := cli.SetValidateServerCertificate(); err != nil {
		t.Fatalf("expected success, but failed")
	}
	cli.Info()

	t.Logf("client: took %s", time.Since(timerStartTime))
}
