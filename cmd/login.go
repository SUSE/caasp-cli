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
	"net/url"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	v1 "k8s.io/client-go/pkg/api/v1"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
)

type loginDetails struct {
	server       string
	username     string
	password     string
	rootCA       string
	clusterName  string
	token        string
	refreshToken string
}

var login loginDetails

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to a CaaSP cluster",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		cluster, ok := kubeConfig.Clusters[login.clusterName]
		if !ok {
			cluster = &api.Cluster{
				Server:                login.server,
				InsecureSkipTLSVerify: skipTLS,
			}
		}

		serverURL := ""
		if ok {
			serverURL = cluster.Server
		}

		if serverURL == "" {
			serverURL = login.server
		}

		if serverURL == "" {
			return fmt.Errorf("you must specify --server")
		}

		dexServiceURL, err := findDex(serverURL)
		if err != nil {
			return fmt.Errorf("unable to find Dex service in CaaSP cluster, error was %s", err.Error())
		}

		authRequest := AuthRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			IssuerURL:    dexServiceURL,
			Username:     login.username,
			Password:     login.password,
			RootCAs:      login.rootCA,
		}

		authResponse, err := Auth(authRequest)
		if err != nil {
			fmt.Println("Unable to auth, error was", err.Error())
		}

		spew.Dump("clusters", kubeConfig.Clusters)

		spew.Dump("authResponse", authResponse)

		spew.Dump("dex service", dexServiceURL)

		return nil
	},
}

func init() {
	RootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVarP(&login.server, "server", "s", "", "CaaSP Server URL")
	loginCmd.Flags().StringVarP(&login.username, "username", "u", "", "Username")
	loginCmd.Flags().StringVarP(&login.password, "password", "p", "", "Password")
	loginCmd.Flags().StringVarP(&login.rootCA, "root-ca", "r", "", "Root certificate authority chain file")
	loginCmd.Flags().StringVarP(&login.clusterName, "cluster-name", "n", "local", "Cluster name for kubeconfig file")
}

func findDex(kubeAPI string) (string, error) {
	config, err := clientcmd.BuildConfigFromFlags("", cfgFile)
	if err != nil {
		return "", err
	}

	// go find dex's URL based on the Kubernetes API
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	service, err := clientset.CoreV1().Services("kube-system").Get("dex", meta_v1.GetOptions{})
	if err != nil {
		return "", err
	}

	u, err := url.Parse(kubeAPI)
	if err != nil {
		return "", err
	}

	var dexURL string

	// we ship Dex in a NodePort-based configuration, but it's possible that a user
	// has modified the service type (in response to a cloud deployment or the like)
	// so we should make a best effort to work with that.
	switch service.Spec.Type {
	case v1.ServiceTypeNodePort:
		dexURL = fmt.Sprintf("https://%s:%d", u.Hostname(), service.Spec.Ports[0].NodePort)
	case v1.ServiceTypeClusterIP:
		dexURL = fmt.Sprintf("https://%s:%d", service.Spec.ClusterIP, service.Spec.Ports[0].Port)
	case v1.ServiceTypeLoadBalancer:
	default:
		return "", fmt.Errorf("Dex Service in CaaSP doesn't have a proper type, cannot determine external location")
	}

	return dexURL, nil
}
