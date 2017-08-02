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
		authRequest := AuthRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			IssuerURL:    login.server,
			Username:     login.username,
			Password:     login.password,
			RootCAs:      login.rootCA,
		}

		authResponse, err := Auth(authRequest)
		if err != nil {
			fmt.Println("Unable to auth, error was", err.Error())
		}

		spew.Dump("authResponse", authResponse)

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
