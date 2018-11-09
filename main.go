package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	flag "github.com/spf13/pflag"

	keyprotect "github.com/locke105/kp/client"
)

func PrettyJson(data []byte) []byte {
	var prettified bytes.Buffer
	json.Indent(&prettified, data, "", "  ")
	return prettified.Bytes()
}

func usage() {
	flag.Usage()
	os.Exit(1)
}

var (
	flagVars []flagVar
)

type flagVar struct {
	variable    *string
	name        string
	value       string
	description string
	required    bool
	pflagVar    *string
}

func FlagVar(variable *string, name string, value string, description string, required bool) {
	var flagHolder string
	f := flagVar{variable, name, value, description, required, &flagHolder}
	flag.StringVar(&flagHolder, f.name, f.value, f.description)
	flagVars = append(flagVars, f)
}

func Parse() {
	flag.Parse()

	for _, f := range flagVars {
		envName := strings.ToUpper(strings.Replace("kp-"+f.name, "-", "_", -1))
		finalVal := os.Getenv(envName)

		if (*f.pflagVar) != "" {
			finalVal = (*f.pflagVar)
		}

		if finalVal == "" && f.required {
			log.Fatalln(fmt.Sprintf("Must specify %s or set %s", f.name, envName))
		}

		(*f.variable) = finalVal
	}
}

func main() {
	flag.ErrHelp = errors.New("KeyProtect CLI")

	var instanceId string
	var iamToken string
	var region string

	FlagVar(&instanceId, "instance-id", "", "Instance UUID for KP service", true)
	FlagVar(&iamToken, "iam-token", "", "IAM Auth Token from Bluemix/IBM Cloud client", true)
	FlagVar(&region, "region", "", "Region name to use", true)
	Parse()

	if !strings.HasPrefix(iamToken, "bearer") && !strings.HasPrefix(iamToken, "Bearer") {
		iamToken = fmt.Sprintf("Bearer %s", iamToken)
	}

	args := flag.Args()
	var subcommand string
	if len(args) == 0 {
		usage()
	} else {
		subcommand = args[0]
	}

	kp := keyprotect.NewKPClient(instanceId, iamToken, region)

	switch subcommand {
	case "list":
		keys := kp.List()
		fmt.Printf("ID\tNAME\n")
		for _, key := range keys {
			fullKey := kp.Get(key.Id())
			fmt.Printf("%s\t%s\n", fullKey.Id(), fullKey["name"])
		}
	case "create":
		if len(args) < 2 {
			log.Fatal("name argument required for create")
		}
		name := args[1]
		key, err := kp.Generate(name)
		if err == nil {
			fmt.Printf("ID\tNAME\n")
			fmt.Printf("%s\t%s\n", key.Id(), key["name"])
		} else {
			log.Fatalf("Error creating key: %s", err)
		}
	case "delete":
		if len(args) < 2 {
			log.Fatal("ID argument required for delete")
		}
		keyId := args[1]
		err := kp.Delete(keyId)
		if err == nil {
			fmt.Printf("Deleted key: %s\n", keyId)
		} else {
			log.Fatalf("Error deleting key: %s", err)
		}
	default:
		usage()
	}

}
