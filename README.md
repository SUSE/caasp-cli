[![Build Status](https://travis-ci.org/kubic-project/caasp-cli.svg?branch=master)](https://travis-ci.org/kubic-project/caasp-cli)

# CaaS Platform CLI

This is the command line client for interacting with a CaaS Platform cluster (v1, v2 and v3 only).

## Supported commands

```text
SUSE CaaS Platform CLI

Usage:
  caasp-cli [command]

Available Commands:
  help        Help about any command
  login       Login to a CaaS Platform cluster
  status      A brief description of your command

Flags:
      --debug-http            Debug HTTP connections
  -h, --help                  help for caasp-cli
      --kubeconfig string     config file (default is $HOME/.kube/config)
  -k, --skip-tls-validation   Skip TLS validation

Use "caasp-cli [command] --help" for more information about a command.
```

### Login

```text
Login to a CaaS Platform cluster

Usage:
  caasp-cli login [flags]

Flags:
  -n, --cluster-name string   Cluster name for kubeconfig file (default "local")
  -h, --help                  help for login
  -p, --password string       Password
  -r, --root-ca string        Root certificate authority chain file
  -s, --server string         CaaS Platform Server URL
  -u, --username string       Username

Global Flags:
      --debug-http            Debug HTTP connections
      --kubeconfig string     config file (default is $HOME/.kube/config)
  -k, --skip-tls-validation   Skip TLS validation
```

Example:

```bash
./caasp-cli login -u admin -p MyMagicPassword -s https://b1f6811e5dfc49e6b3b99818207e75c8.infra.caasp.local:32000 -r ~/SUSE_Trust_CA.crt 
```

## LICENSE

Released under Apache Public License 2.0. See LICENSE.
