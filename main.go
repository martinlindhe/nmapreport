package main

import (
	"encoding/xml"
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

type Report struct {
	Hosts []Host
}

type Host struct {
	State        string // up/down
	StatusReason string // arp-response
	Addresses    []string
	Hostnames    []string
	Os           []string
	OsTypes      []string
	Ports        []Port
}

type Port struct {
	Banner string
	Recon  []string
}

func main() {

	_ = kong.Parse(&args,
		kong.Name("nmapreport"),
		kong.Description("Produce a pretty report from a nmap xml"))

	data, err := ioutil.ReadFile(args.Filename)
	if err != nil {
		log.Fatal(err)
	}

	report, err := report(data)
	if err != nil {
		log.Fatal(err)
	}

	output, err := xml.MarshalIndent(&report, "  ", "    ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(output))
}

func report(data []byte) (*Report, error) {
	res, err := nmap.Parse(data)
	if err != nil {
		return nil, err
	}

	fs := recog.NewFingerprintSet()
	fs.LoadFingerprints()

	report := Report{}

	for _, host := range res.Hosts {
		repHost := Host{State: host.Status.State, StatusReason: host.Status.Reason}

		for _, adr := range host.Addresses {
			repHost.Addresses = append(repHost.Addresses, adr.AddrType+":"+adr.Vendor+":"+adr.Addr)
		}

		if len(host.Hostnames) > 0 {
			for _, h := range host.Hostnames {
				repHost.Hostnames = append(repHost.Hostnames, h.Type+":"+h.Name)
			}
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
		repHost.Os = oses
		repHost.OsTypes = osTypes

		for _, port := range host.Ports {
			repPort := Port{
				Banner: fmt.Sprintf("%s:%d %s (%s) -- %s %s (%s)", port.Protocol, port.PortId, port.State.State, port.State.Reason, port.Service.Name, port.Service.Method, port.Service.ExtraInfo),
			}

			if port.Service.ServiceFp != "" {
				values := []string{}
				for key := range fs.Databases {
					if !strings.HasSuffix(key, ".xml") {
						continue
					}
					match := fs.MatchFirst(key, port.Service.ServiceFp)
					if match.Matched {
						for k, v := range match.Values {
							if v != "" && v != "0.0" {
								values = append(values, key+"@"+k+":"+v)
							}
						}
					}
				}
				repPort.Recon = values
			}
			repHost.Ports = append(repHost.Ports, repPort)
		}

		report.Hosts = append(report.Hosts, repHost)
	}
	return &report, nil
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
