package main

import (
	"net"
	"strings"

	"github.com/jsimonetti/lldpd"
)

func main() {
	srv := lldpd.New(
		lldpd.InterfaceFilter(filterFn),
		lldpd.PortLookup(portDescFn),
		lldpd.SourceAddress(net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}),
	)
	srv.Listen()
}

func filterFn(ifi *net.Interface) bool {
	if ifi == nil {
		return false
	}
	if strings.HasPrefix(ifi.Name, "enp") {
		return true
	}
	if strings.HasPrefix(ifi.Name, "wlp") {
		return true
	}
	return false
}

func portDescFn(ifi *net.Interface) string {
	if strings.HasPrefix(ifi.Name, "enp") {
		return "wired"
	}
	if strings.HasPrefix(ifi.Name, "wlp") {
		return "wireless"
	}
	return ifi.Name
}
