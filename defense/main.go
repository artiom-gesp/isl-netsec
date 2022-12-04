package main

import (
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
	spath "github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
// Global constants
)

var ip_map = make(map[string]time.Time)
var mac_map = make(map[string]time.Time)
var ip_count = make(map[string]int)
var mac_save = make(map[string]map[string]bool)
var time_last_ddos time.Time = time.Time{}
var block_ip bool
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
	raw := make([]byte, scion.Path.Len())
	scion.Path.SerializeTo(raw)
	path := &spath.Decoded{}
	path.DecodeFromBytes(raw)

	arr := scion.RawSrcAddr
	arr2 := path.HopFields[0].Mac
	src_ip := string(arr[:])
	src_mac := string(arr2[:])

	if time.Since(time_last_ddos) > 500000000 {
		// fmt.Println("RESET!")
		// for key, val := range mac_save {
		// 	fmt.Print("mac: ")
		// 	for _, b := range []byte(key) {
		// 		fmt.Printf("%d ", b)
		// 	}
		// 	fmt.Printf(", diff ip: %d\n", len(val))
		// }
		// fmt.Printf("IP HAS BEEN BLOCKED: %d", block_ip)
		time_last_ddos = time.Now()
		ip_map = make(map[string]time.Time)
		mac_map = make(map[string]time.Time)
		ip_count = make(map[string]int)
		mac_save = make(map[string]map[string]bool)
		block_ip = false

	} else {
		time_last_ddos = time.Now()
	}

	time_since_ip, exists := ip_map[src_ip]
	time_since_hop, exists2 := mac_map[src_mac]
	if !exists2 {
		mac_save[src_mac] = make(map[string]bool)
	} else {
		// if mac_count[src_mac] >= 40 {
		// 	return false
		// }
	}

	// if exists && time.Since(time_since_ip)+time.Since(time_since_hop) > 2*350000000+time.Duration(math.Pow(1.5, float64(f_map[src_ip])))*1000000000 {
	// if exists && time.Since(time_since_ip) > 350000000 {
	// for _, val := range mac_save {
	// 	fmt.Printf("IP: %s, IP count: %d, MAC count:%d\n", val.ip, val.count_ip, mac_count[val.mac])
	// }
	ret := true
	if exists && time.Since(time_since_ip) > 350000000 {
		ip_map[src_ip] = time.Now()
	} else if exists {
		ret = false
		// fmt.Println("BLOCKED BY IP")
		block_ip = true
	} else {
		ip_map[src_ip] = time.Now()
		ip_count[src_ip] = 0
	}
	ip_count[src_ip] += 1

	if exists2 && time.Since(time_since_hop) > 14000000 {
		mac_map[src_mac] = time.Now()
	} else if exists2 && !block_ip {
		// fmt.Println("BLOCKED BY MAC")
		ret = false
	} else {
		mac_map[src_mac] = time.Now()
	}

	// fmt.Println(scion.Payload)
	mac_save[src_mac][src_ip] = true
	if len(mac_save[src_mac]) >= 5 && !block_ip {
		// if len(ip_count) >= 150 && ip_count[src_ip] == 1 && !block_ip {
		// fmt.Println("BLOCKED BY NB")
		ret = false
	}
	// prettyPrintSCION(scion)
	// prettyPrintUDP(udp)
	// SAME FIRS HOP, DIFFERENT IP!

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
	return ret
}

func init() {
	// Perform any initial setup here
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
