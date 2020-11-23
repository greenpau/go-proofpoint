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

package main

import (
	"flag"
	"fmt"
	"github.com/greenpau/go-proofpoint"
	"github.com/greenpau/versioned"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
)

func init() {
	app = versioned.NewPackageManager("ppcli")
	app.Description = "Proofpoint API Client"
	app.Documentation = "https://github.com/greenpau/go-proofpoint/"
	app.SetVersion(appVersion, "1.0.2")
	app.SetGitBranch(gitBranch, "main")
	app.SetGitCommit(gitCommit, "3d03a23")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

func main() {
	var logLevel string
	var isShowVersion bool
	var configDir string
	var configFile string
	var servicePrincipal, principalSecret string
	var serviceName string
	var serviceOperation string

	flag.StringVar(&configFile, "config", "", "configuration file")
	flag.StringVar(&servicePrincipal, "service-principal", "", "API Service Principal")
	flag.StringVar(&principalSecret, "principal-secret", "", "API Principal Secret")

	flag.StringVar(&serviceName, "service-name", "", "API Service Name, e.g. siem")
	flag.StringVar(&serviceOperation, "service-operation", "", "API Service Operation, e.g. all, issues, etc.")

	flag.StringVar(&logLevel, "log-level", "info", "logging severity level")
	flag.BoolVar(&isShowVersion, "version", false, "show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%s - %s\n\n", app.Name, app.Description)
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments]\n\n", app.Name)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDocumentation: %s\n\n", app.Documentation)
	}
	flag.Parse()

	if isShowVersion {
		fmt.Fprintf(os.Stdout, "%s\n", app.Banner())
		os.Exit(0)
	}

	// Determine configuration file name and extension
	if configFile == "" {
		configDir = "."
		configFile = app.Name + ".yaml"
	} else {
		configDir, configFile = filepath.Split(configFile)
	}
	configFileExt := filepath.Ext(configFile)
	if configFileExt == "" {
		fmt.Fprintf(os.Stderr, "--config specifies a file without an extension, e.g. .yaml or .json\n")
		os.Exit(1)
	}

	configName := strings.TrimSuffix(configFile, configFileExt)
	viper.SetConfigName(configName)
	viper.SetEnvPrefix("proofpoint")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_", " ", "_"))
	viper.AddConfigPath("$HOME/.config/" + app.Name)
	viper.AddConfigPath(configDir)
	viper.AutomaticEnv()

	// Obtain settings via environment variable
	if servicePrincipal == "" {
		if v := viper.Get("service-principal"); v != nil {
			servicePrincipal = viper.Get("service-principal").(string)
		}
	}
	if principalSecret == "" {
		if v := viper.Get("principal-secret"); v != nil {
			principalSecret = viper.Get("principal-secret").(string)
		}
	}

	// Obtain settings via configuration file
	if err := viper.ReadInConfig(); err == nil {
		if servicePrincipal == "" {
			if v := viper.Get("service_principal"); v != nil {
				servicePrincipal = viper.Get("service_principal").(string)
			}
		}
		if principalSecret == "" {
			if v := viper.Get("principal_secret"); v != nil {
				principalSecret = viper.Get("principal_secret").(string)
			}
		}
	} else {
		if !strings.Contains(err.Error(), "Not Found in") {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	}

	opts := make(map[string]interface{})
	opts["log_level"] = logLevel
	cli, err := proofpoint.NewClient(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	defer cli.Close()

	if err := cli.SetServicePrincipal(servicePrincipal); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if err := cli.SetPrincipalSecret(principalSecret); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	cli.Info()

	opts = make(map[string]interface{})
	items, err := cli.GetData(serviceName, serviceOperation, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	for _, item := range items {
		fmt.Fprintf(os.Stdout, "%s\n", item)
	}
}
