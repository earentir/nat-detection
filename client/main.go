package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/earentir/nat-detection/internal/stun"
)

// -------- flags ----------
var (
	sfServer  = flag.String("server", "stun.l.google.com:19302", "STUN server host:port")
	sfEcho    = flag.String("echo", "", "TCP echo host:port (fallback). If empty, uses same host on :8080")
	sfIface   = flag.String("iface", "", "interface name to test")
	sfAll     = flag.Bool("all-ifaces", false, "iterate through every up interface")
	sfProto   = flag.String("proto", "auto", "auto|udp|tcp")
	sfTimeout = flag.Duration("timeout", 3*time.Second, "network timeout")
)

func usage() {
	fmt.Fprintf(os.Stderr, "natcheck [flags]\n\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if !*sfAll && *sfIface == "" {
		fmt.Fprintln(os.Stderr, "either --iface or --all-ifaces required")
		os.Exit(1)
	}

	ctx := context.Background()

	ifaces := []net.Interface{}
	if *sfAll {
		all, _ := net.Interfaces()
		for _, ifc := range all {
			if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0 {
				ifaces = append(ifaces, ifc)
			}
		}
	} else {
		ifc, err := net.InterfaceByName(*sfIface)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ifaces = []net.Interface{*ifc}
	}

	for _, ifc := range ifaces {
		testFamily(ctx, &ifc, "udp4")
		testFamily(ctx, &ifc, "udp6")
	}
}

// Result holds the result of a NAT test.
type Result struct {
	Family      string
	OutsideAddr string
	InsideAddr  string
	Error       error
}

func testFamily(ctx context.Context, ifc *net.Interface, network string) {
	proto := *sfProto
	if proto == "auto" {
		proto = "udp"
	}

	v4 := strings.HasSuffix(network, "4")
	// dialNet := network
	// if proto == "tcp" {
	// 	dialNet = strings.TrimSuffix(network, "udp") + "tcp"
	// }

	var res Result
	res.Family = "IPv4"
	if !v4 {
		res.Family = "IPv6"
	}

	// gather a local address for this interface/family
	addrs, _ := ifc.Addrs()
	var localIP net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 && ipNet.IP.To4() != nil {
			localIP = ipNet.IP
			break
		}
		if !v4 && ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
			localIP = ipNet.IP
			break
		}
	}
	if localIP == nil {
		fmt.Printf("%s / %s  — skipping (no address)\n", ifc.Name, res.Family)
		return
	}

	dialer := net.Dialer{
		Timeout:   *sfTimeout,
		LocalAddr: &net.UDPAddr{IP: localIP},
	}

	switch proto {
	case "udp":
		res = udpProbe(ctx, &dialer, ifc, v4)
	case "tcp":
		res = tcpProbe(ctx, &dialer, ifc, v4)
	default:
		fmt.Println("unknown proto:", proto)
		return
	}

	printResult(ifc.Name, res)
}

func udpProbe(ctx context.Context, d *net.Dialer, ifc *net.Interface, v4 bool) Result {
	fam := "udp4"
	if !v4 {
		fam = "udp6"
	}
	conn, err := d.DialContext(ctx, fam, *sfServer)
	if err != nil {
		return Result{Error: err}
	}
	defer conn.Close()

	id := stun.RandomTransactionID()
	req := stun.BuildBindingRequest(id)
	conn.SetDeadline(time.Now().Add(*sfTimeout))
	if _, err := conn.Write(req); err != nil {
		return Result{Error: err}
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{Error: err}
	}

	ip, port, err := stun.ParseXORMapped(buf[:n])
	if err != nil {
		return Result{Error: err}
	}

	outside := fmt.Sprintf("%s:%d", ip, port)
	inside := conn.LocalAddr().String()
	return Result{OutsideAddr: outside, InsideAddr: inside}
}

func tcpProbe(ctx context.Context, d *net.Dialer, ifc *net.Interface, v4 bool) Result {
	target := *sfEcho
	if target == "" {
		host, _, _ := net.SplitHostPort(*sfServer)
		target = net.JoinHostPort(host, "8080")
	}
	fam := "tcp4"
	if !v4 {
		fam = "tcp6"
	}
	conn, err := d.DialContext(ctx, fam, target)
	if err != nil {
		return Result{Error: err}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(*sfTimeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return Result{Error: err}
	}
	outside := strings.TrimSpace(line)
	inside := conn.LocalAddr().String()
	return Result{OutsideAddr: outside, InsideAddr: inside}
}

func printResult(ifName string, r Result) {
	tag := "❓"
	switch {
	case r.Error != nil:
		tag = "✗"
	case insideEqualsOutside(r):
		tag = "✅"
	default:
		tag = "🔒"
	}
	fmt.Printf("%s / %s  %s ", ifName, r.Family, tag)
	if r.Error != nil {
		fmt.Printf("%v\n", r.Error)
		return
	}
	fmt.Printf("(outside %s, inside %s)\n", r.OutsideAddr, r.InsideAddr)
}

func insideEqualsOutside(r Result) bool {
	return r.OutsideAddr == r.InsideAddr
}
