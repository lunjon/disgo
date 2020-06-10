package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/steabert/disgo/pkg/scan"
	"net"
	"os"
	"time"
)

type protocols struct {
	values []scan.Protocol
}

func newProtoFlag() *protocols {
	return &protocols{
		values: []scan.Protocol{scan.SSDP, scan.MDNS},
	}
}

func (f *protocols) Set(s string) error {
	p, err := scan.ParseProtocols(s)
	f.values = p
	return err
}

func (f *protocols) String() string {
	return "SSDP, MDNS"
}

func (f *protocols) Type() string {
	return "string"
}

var (
	protoFlag = newProtoFlag()
)

// Build creates the root command to be executed for disgo.
func Build() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "disgo",
		Short: "Network device discovery.",
	}

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan network devices over SSDP and MDNS.",
		Run:   runScan,
	}

	scanCmd.Flags().DurationP("timeout", "t", time.Second * 10, "Timeout to use.")
	scanCmd.Flags().VarP(protoFlag, "protocol", "p", "Comma separated list of protocols to use.")

	rootCmd.AddCommand(scanCmd)
	return rootCmd
}

func runScan(cmd *cobra.Command, args []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("failed to get interfaces: %v\n", err)
		os.Exit(1)
	}

	d, _ := cmd.Flags().GetDuration("timeout")

	timeout := time.Tick(d)
	results := make(chan scan.Discovery)
	errors := make(chan error)

	for _, protocol := range protoFlag.values {
		switch protocol {
		case scan.SSDP:
			scan.ScanSSPD(ifaces, results, errors)
		case scan.MDNS:
			scan.ScanMDNS(ifaces, results, errors)
		}
	}

	running := true
	for running {
		select {
		case <-timeout:
			running = false
		case err := <-errors:
			fmt.Printf("Error: %v\n", err)
		case discover := <-results:
			fmt.Println(discover.Message)
		}
	}
}
