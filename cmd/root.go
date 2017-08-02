// Copyright © 2017 SUSE
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/runtime/schema"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

const (
	clientID     = "caasp-cli"
	clientSecret = "swac7qakes7AvucH8bRucucH"
)

var (
	cfgFile    string
	skipTLS    bool
	kubeConfig *clientcmdapi.Config
	debugHTTP  bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "caasp-cli",
	Short: "SUSE CaaSP CLI",
	Long:  "",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	cfg, err := homedir.Dir()
	if err != nil {
		fmt.Println("Unable to determine home directory!")
		fmt.Println("Error was:", err)
		os.Exit(1)
	}

	cfg = path.Join(cfg, ".kube", "config")
	cfgEnv := os.Getenv("KUBECONFIG")
	var defCfgFile string
	if cfgEnv != "" {
		defCfgFile = cfgEnv
	} else {
		defCfgFile = cfg
	}

	RootCmd.PersistentFlags().StringVar(&cfgFile, "kubeconfig", defCfgFile, "config file (default is $HOME/.kube/config)")
	RootCmd.PersistentFlags().BoolVarP(&skipTLS, "skip-tls-validation", "k", false, "Skip TLS validation")
	RootCmd.PersistentFlags().BoolVar(&debugHTTP, "debug-http", false, "Debug HTTP connections")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	kubecfgBytes, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		fmt.Println("Unable to read kubeconfig file: ", cfgFile)
		fmt.Println("Error was:", err)
		os.Exit(1)
	}

	kubeConfig := clientcmdapi.NewConfig()
	if len(kubecfgBytes) == 0 {
		fmt.Println("No kubeconfig file found on disk, starting new configuration")
		return
	}

	decoded, _, err := clientcmdlatest.Codec.Decode(kubecfgBytes, &schema.GroupVersionKind{Version: clientcmdlatest.Version, Kind: "Config"},
		kubeConfig)
	if err != nil {
		fmt.Println("Unable to parse existing kubeconfig!")
		fmt.Println("Error was: ", err)
		os.Exit(1)
	}
	kubeConfig = decoded.(*clientcmdapi.Config)
}
