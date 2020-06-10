package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	ssdp4Address = "239.255.255.250"
	ssdp6Address = "ff0e::c"
	ssdpPort     = 1900
)

var (
	ssdp4UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp4Address), Port: ssdpPort}
	ssdp6UDPAddress = net.UDPAddr{IP: net.ParseIP(ssdp6Address), Port: ssdpPort}
)

func buildMessage(dst *net.UDPAddr) string {
	lines := []string{
		"M-SEARCH * HTTP/1.1",
		"HOST:" + dst.String(),
		`MAN:"ssdp:discover"`,
		"ST: ssdp:all",
		"MX: 1",
		"\r\n",
	}
	return strings.Join(lines, "\r\n")
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func ssdpQuery(conn *net.UDPConn, dst *net.UDPAddr, errors chan error) {
	_, err := conn.WriteToUDP([]byte(buildMessage(dst)), dst)
	if err != nil {
		errors <- err
	}
}

// Send an M-SEARCH packet on an UDP connection to a UDP destination address
func ssdpListen(conn *net.UDPConn, results chan Discovery, errors chan error) {
	buffer := make([]byte, 1024)

	for {
		size, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			errors <- fmt.Errorf("failed to read from UDP: %v", err)
		}

		var server string
		reader := bufio.NewReader(bytes.NewReader(buffer[:size]))
		req := &http.Request{} // Needed for ReadResponse but doesn't have to be real
		rsp, err := http.ReadResponse(reader, req)
		if err != nil {
			server = "[parser error]"
		} else {
			server = rsp.Header["Server"][0]
		}

		// Log

		discover := Discovery{
			Protocol: SSDP,
			IP:       src.IP.String(),
			Message:  fmt.Sprintf("%-24s [%s] %s", src.IP, "SSDP", server),
		}
		results <- discover
	}
}

func ScanSSPD(ifaces []net.Interface, results chan Discovery, errors chan error) {
	for _, iface := range ifaces {
		ifAddrs, err := iface.Addrs()
		if err != nil {
			errors <- err
			return
		}

		for _, ifAddr := range ifAddrs {
			ip, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				errors <- fmt.Errorf("failed to parse CIDR: %v", err)
				continue
			}

			var multicastAddr net.UDPAddr
			if ip.To4() != nil {
				multicastAddr = ssdp4UDPAddress
			} else {
				multicastAddr = ssdp6UDPAddress
			}

			ifAddrUDP := net.UDPAddr{IP: ip, Port: 0, Zone: iface.Name}
			ifAddrConn, err := net.ListenUDP("udp", &ifAddrUDP)
			if err != nil {
				errors <- fmt.Errorf("failed to listen on UDP: %v", err)
				continue
			}

			go ssdpListen(ifAddrConn, results, errors)

			ssdpQuery(ifAddrConn, &multicastAddr, errors)
		}
	}
}
