package scan

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

// mDNS

const (
	mdns4Address = "224.0.0.251"
	mdns6Address = "ff02::fb"
	mdnsPort     = 5353
)

var (
	mdns4UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns4Address), Port: mdnsPort}
	mdns6UDPAddress = net.UDPAddr{IP: net.ParseIP(mdns6Address), Port: mdnsPort}
)

func mdnsQuery(conn *net.UDPConn, dst *net.UDPAddr, errors chan error) {

	// Build DNS message

	m := new(dns.Msg)
	m.SetQuestion("_googlecast._tcp.local.", dns.TypePTR)
	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	m.Question[0].Qclass |= 1 << 15
	m.RecursionDesired = false
	data, err := m.Pack()
	if err != nil {
		errors <- err
		return
	}

	// Send

	_, err = conn.WriteToUDP(data, dst)
	if err != nil {
		errors <- err
	}
}

func mdnsListen(conn *net.UDPConn, results chan Discovery, errors chan error) {
	buffer := make([]byte, 1024)

	for {
		// Read

		size, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			errors <- err
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buffer[:size]); err != nil {
			errors <- err
			return
		}

		// Log

		for _, answer := range msg.Answer {
			d := Discovery{
				Protocol: MDNS,
				IP:       src.IP.String(),
				Message:  fmt.Sprintf("%-24s [%s] %s", src.IP, "mDNS", answer.String()),
			}
			results <- d
		}
	}
}

func ScanMDNS(ifaces []net.Interface, results chan Discovery, errors chan error) {
	for _, iface := range ifaces {

		// Join multicast group and listen.

		mdnsMulticastConn4, err := net.ListenMulticastUDP("udp4", &iface, &mdns4UDPAddress)
		if err != nil {
			errors <- err
			return
		}

		go mdnsListen(mdnsMulticastConn4, results, errors)

		mdnsMulticastConn6, err := net.ListenMulticastUDP("udp6", &iface, &mdns6UDPAddress)
		if err != nil {
			errors <- err
			return
		}

		go mdnsListen(mdnsMulticastConn6, results, errors)

		// Send question to multicast and listen for unicast reponses on interfaces addresses.

		ifAddrs, err := iface.Addrs()
		if err != nil {
			errors <- err
			return
		}
		for _, ifAddr := range ifAddrs {
			ip, _, err := net.ParseCIDR(ifAddr.String())
			if err != nil {
				errors <- err
				continue
			}

			var multicastAddr net.UDPAddr
			if ip.To4() != nil {
				multicastAddr = mdns4UDPAddress
			} else {
				multicastAddr = mdns6UDPAddress
			}

			ifAddrUDP := net.UDPAddr{IP: ip, Port: 0, Zone: iface.Name}
			ifAddrConn, err := net.ListenUDP("udp", &ifAddrUDP)

			if err != nil {
				errors <- err
				continue
			}

			go mdnsListen(ifAddrConn, results, errors)

			mdnsQuery(ifAddrConn, &multicastAddr, errors)
		}
	}
}
