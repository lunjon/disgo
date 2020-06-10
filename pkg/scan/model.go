package scan

import (
	"fmt"
	"strings"
)


type Protocol string

func (p Protocol) String() string {
	return string(p)
}

// ParseProtocol parses a string s into the corresponding
// Protocol type.
func ParseProtocol(s string) (p Protocol, err error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "s", "ssdp":
		p = SSDP
	case "m", "mdns":
		p = MDNS
	default:
		err = fmt.Errorf("invalid protocol: %s", s)
	}

	return
}

// ParseProtocols parses a string consisting of a comma separated
// list of protocol names into a slice of Protocol type.
func ParseProtocols(s string) ([]Protocol, error) {
	var values []Protocol
	for _, s := range strings.Split(s, ",") {
		p, err := ParseProtocol(s)
		if err != nil {
			return nil, err
		}

		values = append(values, p)
	}
	return values, nil
}

const (
	SSDP Protocol = "SSDP"
	MDNS Protocol = "MDNS"
)

// Discovery represents a network device discovery.
type Discovery struct {
	Protocol Protocol
	IP       string
	Message  string
}
