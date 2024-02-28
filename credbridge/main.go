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

func getKeys(keytype *string, debug *bool) {
	creds := getCredentials()
	if *debug {
		fmt.Fprintf(os.Stderr, "%+v\n", creds)
	}
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
	var debug *bool = parser.Flag("d", "debug", nil)
	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
		os.Exit(1)
	}

	if len(*keytype) == 0 {
		log.Fatal(parser.Usage(err))
		os.Exit(1)
	}

	getKeys(keytype, debug)
}

/*
 Copyright Valid Eval, 2024

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
*/
