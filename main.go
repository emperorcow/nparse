package main

import (
	"io/ioutil"
	"fmt"
	"os"
	"strings"

	"github.com/lair-framework/go-nmap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("ERROR: You did not specify an input file.\n")
		os.Exit(1)
	}
	file := os.Args[1]

	if _, err := os.Stat(file); err != nil {
		fmt.Printf("ERROR: File '%s' does not exist\n", file)
		os.Exit(1)
	}

	parseNmap(file)
}

func parseNmap(inFile string) {
	data, err := ioutil.ReadFile(inFile)
	if err != nil {
		fmt.Printf("ERROR: Could not read input file(%s): %s\n", inFile, err.Error())
		os.Exit(1)
	}

	parsed, err := nmap.Parse(data)
	if err != nil {
		fmt.Printf("ERROR: Could not parse input file(%s): %s\n", inFile, err.Error())
		os.Exit(1)
	}

	fmt.Printf("IP, HOST, PROTO, PORT, SERVICE\n")

	hosts := parsed.Hosts
	for _, host := range hosts {
		ipAddr := "<UNKNOWN>"
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ipAddr = addr.Addr
			}
		}

		var tmpNames []string
		for _, name := range host.Hostnames {
			tmpNames = append(tmpNames, name.Name)
		}
		hostname := strings.Join(tmpNames, ",")

		for _, port := range host.Ports {
			if port.State.State == "open" {
				portID := port.PortId
				portProto := port.Protocol
				portSvc := port.Service.Name

				fmt.Printf("%s,\"%s\",%s,%d,%s\n", ipAddr, hostname, portProto, portID, portSvc)
			}
		}
	}
}
