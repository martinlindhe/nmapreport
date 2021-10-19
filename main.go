package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/RumbleDiscovery/recog-go"
	"github.com/alecthomas/kong"
	"github.com/lair-framework/go-nmap"
)

var args struct {
	Filename string `kong:"arg" name:"filename" type:"existingfile" help:"Input nmap xml."`
}

func main() {

	_ = kong.Parse(&args,
		kong.Name("nmapreport"),
		kong.Description("Produce a pretty report from a nmap xml"))

	data, err := ioutil.ReadFile(args.Filename)
	if err != nil {
		log.Fatal(err)
	}

	res, err := nmap.Parse(data)
	if err != nil {
		log.Fatal(err)
	}

	fs := recog.NewFingerprintSet()
	fs.LoadFingerprints()

	for _, host := range res.Hosts {
		fmt.Printf("HOST: %s (reason %s)\n", host.Status.State, host.Status.Reason)

		// addresses
		addresses := []string{}
		for _, adr := range host.Addresses {
			addresses = append(addresses, adr.AddrType+":"+adr.Vendor+":"+adr.Addr)
		}
		fmt.Println("-- addresses:", strings.Join(addresses, ", "))

		if len(host.Hostnames) > 0 {

			hostnames := []string{}
			for _, h := range host.Hostnames {
				hostnames = append(hostnames, h.Type+":"+h.Name)
			}
			fmt.Println("-- hostnames:", strings.Join(hostnames, ", "))
		}

		oses := []string{}
		osTypes := []string{} // "phone", "general purpose"
		for _, os := range host.Os.OsMatches {
			oses = append(oses, fmt.Sprintf("%s%%: %s", os.Accuracy, os.Name))
			for _, osType := range os.OsClasses {
				if !containsString(osTypes, osType.Type) {
					osTypes = append(osTypes, osType.Type)
				}
			}
			break // only show first match
		}
		fmt.Println("-- OS:", strings.Join(oses, ", "))
		fmt.Println("-- Type:", strings.Join(osTypes, ", "))

		for _, port := range host.Ports {
			fmt.Printf("-- port %s:%d %s (%s) -- %s %s (%s)\n", port.Protocol, port.PortId, port.State.State, port.State.Reason, port.Service.Name, port.Service.Method, port.Service.ExtraInfo)

			if port.Service.ServiceFp == "" {
				continue
			}
			//fmt.Printf("      %s\n", port.Service.ServiceFp)

			for key, _ := range fs.Databases {
				if !strings.HasSuffix(key, ".xml") {
					continue
				}
				match := fs.MatchFirst(key, port.Service.ServiceFp)
				if match.Matched {

					values := map[string]string{}
					for key, v := range match.Values {
						if v != "" && v != "0.0" {
							values[key] = v
						}
					}

					fmt.Println("------ recon: ", key, values)
				}
			}
		}

		fmt.Println()
	}
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
