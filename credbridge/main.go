package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func getCredentials() aws.Credentials {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}
	//fmt.Printf("%+v\n", creds)
	return creds
}

func getKeys(keytype *string) {
	creds := getCredentials()
	switch *keytype {
	case "access":
		fmt.Println(creds.AccessKeyID)
	case "secret":
		fmt.Println(creds.SecretAccessKey)
	case "token":
		if creds.Source != "SSOProvider" {
			log.Fatal("Tokens only apply to SSO credentials")
		}
		fmt.Println(creds.SessionToken)
	case "expires":
		if creds.Source != "SSOProvider" {
			log.Fatal("Expires only apply to SSO credentials")
		}
		expires := creds.Expires
		fmt.Println(expires.Format("2006-01-02T15:04:05Z"))
	}
}

func main() {
	parser := argparse.NewParser(
		"credbridge",
		"Returns the current aws access, secret key, session token or expires for your current profile (required)")
	keytype := parser.SelectorPositional([]string{"access", "secret", "token", "expires"}, &argparse.Options{Help: "Key type to return"})
	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
		os.Exit(1)
	}

	if len(*keytype) == 0 {
		log.Fatal(parser.Usage(err))
		os.Exit(1)
	}

	getKeys(keytype)
}
