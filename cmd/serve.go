// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
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
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/golang/glog"
	"github.com/proofpoint/kubernetes-ldap/auth"
	"github.com/proofpoint/kubernetes-ldap/ldap"
	"github.com/proofpoint/kubernetes-ldap/token"
	"github.com/spf13/cobra"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"time"
)

//different flags supported by serve command
var (
	cfgFile string

	ldapHost string
	ldapPort uint

	ldapBaseDn        string
	ldapUserAttribute string

	ldapSearchUserDn       string
	ldapSearchUserPassword string
	usernameAttribute      string

	serverPort              uint
	serverTlsCertFile       string
	serverTlsPrivateKeyFile string

	ldapSkipTlsVerification bool
	ldapUseInsecure         bool

	tokenTtl time.Duration

	// prefix for keypair files (.priv and .pub)
	keypairPrefix string
)

// RootCmd represents the serve command
var RootCmd = &cobra.Command{
	Use:   "kubernetes-ldap",
	Short: "Start the kubernetes-ldap server",
	Long: `kubernetes-ldap exposes two endpoints:
	/ldapAuth - to get a new token
	/authenticate - to verify the token`,
	Run: func(cmd *cobra.Command, args []string) {
		validate()
		serve()
	},
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

	// global command line args for the application.
	RootCmd.PersistentFlags().StringVar(&cfgFile,
		"config",
		"",
		"config file (default is $HOME/.kubernetes-ldap.yaml)")

	RootCmd.Flags().StringVar(&ldapHost, "ldap-host", "", "(Required Host or IP of the LDAP server )")
	RootCmd.Flags().UintVar(&ldapPort, "ldap-port", 389, "LDAP server port")

	RootCmd.Flags().StringVar(&ldapBaseDn, "ldap-base-dn", "", "LDAP user base DN in for form 'dc=example,dc=com")
	RootCmd.Flags().StringVar(&ldapUserAttribute, "ldap-user-attribute", "uid", "LDAP Username attribute for login")

	RootCmd.Flags().StringVar(&ldapSearchUserDn, "ldap-search-user-dn", "", "Search user DN for this app to find users (e.g.: cn=admin,dc=example,dc=com).")
	RootCmd.Flags().StringVar(&ldapSearchUserPassword, "ldap-search-user-password", "", "Search user password")
	RootCmd.Flags().StringVar(&usernameAttribute, "username-attribute", "uid", "ldap attribute to use for Username inside token")

	RootCmd.Flags().UintVar(&serverPort, "port", 4000, "Local port this proxy server will run on")
	RootCmd.Flags().StringVar(&serverTlsCertFile, "tls-cert-file", "", "(Required) File containing x509 Certificate for HTTPS.  (CA cert, if any, concatenated after server cert) .")
	RootCmd.Flags().StringVar(&serverTlsPrivateKeyFile, "tls-private-key-file", "", "(Required) File containing x509 private key matching --tls-cert-file.")

	RootCmd.Flags().BoolVar(&ldapSkipTlsVerification, "ldap-skip-tls-verification", false, "Skip LDAP server TLS verification")
	RootCmd.Flags().BoolVar(&ldapUseInsecure, "use-insecure", false, "Disable LDAP TLS")

	RootCmd.Flags().DurationVar(&tokenTtl, "token-ttl", 24*time.Hour, "TTL for the token")

	RootCmd.PersistentFlags().StringVar(&keypairPrefix, "keypair-prefix", "signing", "Path prefix for keypair files.")
	RootCmd.AddCommand(GenKeypairCmd)

	viper.BindPFlags(RootCmd.Flags())
	viper.BindPFlags(RootCmd.PersistentFlags())
	flag.CommandLine.Parse([]string{})
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".kubernetes-ldap.yaml")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func validate() {
	ldapHost = viper.GetString("ldap-host")
	ldapPort = cast.ToUint(viper.Get("ldap-port"))

	ldapBaseDn = viper.GetString("ldap-base-dn")
	ldapUserAttribute = viper.GetString("ldap-user-attribute")

	ldapSearchUserPassword = viper.GetString("ldap-search-user-password")
	ldapSearchUserDn = viper.GetString("ldap-search-user-dn")

	serverTlsPrivateKeyFile = viper.GetString("tls-private-key-file")
	serverTlsCertFile = viper.GetString("tls-cert-file")

	ldapUseInsecure = viper.GetBool("use-insecure")
	ldapSkipTlsVerification = viper.GetBool("ldap-skip-tls-verification")

	tokenTtl = viper.GetDuration("token-ttl")
	serverPort = cast.ToUint(viper.Get("port"))

	requireFlag("--ldap-host", ldapHost)
	requireFlag("--ldap-base-dn", ldapBaseDn)

	requireFlag("--tls-cert-file", serverTlsCertFile)
	if _, err := os.Stat(serverTlsCertFile); os.IsNotExist(err) {

		fmt.Fprintf(os.Stderr, "file %s does not exist\n", serverTlsCertFile)
		os.Exit(1)
	}

	requireFlag("--tls-private-key", serverTlsPrivateKeyFile)
	if _, err := os.Stat(serverTlsPrivateKeyFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "file %s does not exist\n", serverTlsPrivateKeyFile)
		os.Exit(1)
	}
	keypairPrefix = viper.GetString("keypair-prefix")
}

func requireFlag(flagName string, flagValue string) {
	if flagValue == "" {
		fmt.Fprintf(os.Stderr, "kubernetes-ldap: %s is required. \nUse -h flag for help.\n", flagName)
		os.Exit(1)
	}
}

func serve() error {
	if token.KeypairExists(keypairPrefix) {
		glog.Infof("Using existing keypair in %v", keypairPrefix)
	} else {
		if err := token.GenerateKeypair(keypairPrefix); err != nil {
			glog.Errorf("Error generating key pair: %v", err)
		}
	}

	var err error
	tokenSigner, err := token.NewSigner(keypairPrefix)
	if err != nil {
		glog.Errorf("Error creating token issuer: %v", err)
	}

	tokenVerifier, err := token.NewVerifier(keypairPrefix)
	if err != nil {
		glog.Errorf("Error creating token verifier: %v", err)
	}

	ldapTLSConfig := &tls.Config{
		ServerName:         ldapHost,
		InsecureSkipVerify: ldapSkipTlsVerification,
	}

	ldapClient := &ldap.Client{
		BaseDN:             ldapBaseDn,
		LdapServer:         ldapHost,
		LdapPort:           ldapPort,
		UseInsecure:        ldapUseInsecure,
		UserLoginAttribute: ldapUserAttribute,
		SearchUserDN:       ldapSearchUserDn,
		SearchUserPassword: ldapSearchUserPassword,
		TLSConfig:          ldapTLSConfig,
	}

	server := &http.Server{Addr: fmt.Sprintf(":%d", serverPort)}

	webhook := auth.NewTokenWebhook(tokenVerifier)

	ldapTokenIssuer := &auth.LDAPTokenIssuer{
		LDAPAuthenticator: ldapClient,
		TokenSigner:       tokenSigner,
		TTL:               tokenTtl,
		UsernameAttribute: usernameAttribute,
	}

	// Endpoint for authenticating with token
	http.Handle("/authenticate", webhook)

	// Endpoint for token issuance after LDAP auth
	http.Handle("/ldapAuth", ldapTokenIssuer)

	glog.Infof("Serving on %s", fmt.Sprintf(":%d", serverPort))

	server.TLSConfig = &tls.Config{
		// Change default from SSLv3 to TLSv1.0 (because of POODLE vulnerability)
		MinVersion: tls.VersionTLS10,
	}

	glog.Fatal(server.ListenAndServeTLS(serverTlsCertFile, serverTlsPrivateKeyFile))
	return nil
}

var GenKeypairCmd = &cobra.Command{
	Use:   "gen-keypair",
	Short: "Generate keypair for token signing/verification and exit",
	Long: `Generates a keypair with prefix specified by --keypair-prefix.
	Keypair is written into <keypair-prefix>.priv and <keypair-prefix>.pub.`,
	Run: func(cmd *cobra.Command, args []string) {
		gen_keypair()
	},
}

func gen_keypair() {
	keypairPrefix = viper.GetString("keypair-prefix")
	if err := token.GenerateKeypair(keypairPrefix); err != nil {
		glog.Errorf("Error generating key pair: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Generated keypair in %s.priv %s.pub\n", keypairPrefix, keypairPrefix)
}
