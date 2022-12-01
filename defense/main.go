package main

import (
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
)

const (
// Global constants
)

var ip_map = make(map[string]time.Time)
var ()

// This function receives all packets destined to the customer server.

// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
// - SCION header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
// - UDP header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP

func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	// Print packet contents (disable this before submitting your code)
	// prettyPrintSCION(scion)
	// prettyPrintUDP(udp)
	arr := scion.RawSrcAddr
	src_ip := string(arr[:])

	t, exists := ip_map[src_ip]
	if exists && time.Since(t) > 400000000 {
		ip_map[src_ip] = time.Now()
		// fmt.Println("SACCEPT")
		// prettyPrintSCION(scion)
		// prettyPrintUDP(udp)
		// fmt.Println("NACCEPT")
		return true
	} else if exists {
		// fmt.Println("SBLOCK")
		// prettyPrintSCION(scion)
		// prettyPrintUDP(udp)
		// fmt.Println("NBLOCK")
		return false
	} else {
		ip_map[src_ip] = time.Now()
		return true
	}
	// raw := make([]byte, scion.Path.Len())
	// scion.Path.SerializeTo(raw)
	// path := &spath.Decoded{}
	// path.DecodeFromBytes(raw)

	// if len(path.HopFields) != 5 {
	// 	fmt.Println("SBLOCK")
	// 	prettyPrintSCION(scion)
	// 	prettyPrintUDP(udp)
	// 	fmt.Println("NBLOCK")
	// 	return false
	// }
	// fmt.Println("SACCEPT")
	// prettyPrintSCION(scion)
	// prettyPrintUDP(udp)
	// fmt.Println("NACCEPT")
	// return true
	// fmt.Println(payload)

	// Decision
	// | true  -> forward packet
	// | false -> drop packet
	// return true
}

func init() {
	// Perform any initial setup here
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
