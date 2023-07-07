package main

import (
	"fmt"
	"os"

	"gotcpdump/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

var (
	srcMac  string
	srcIP   string
	srcPort string
	dstMac  string
	dstIP   string
	dstPort string
)

var (
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	dns     layers.DNS
	icmpv4  layers.ICMPv4
	icmpv6  layers.ICMPv6
	payload gopacket.Payload
)

func main() {
	app := &cli.App{
		Name:    "gotcpdump",
		Usage:   "Capture TCP/UDP packets using gopacket",
		Version: "0.0.0",

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "i",
				Aliases: []string{"interface"},
				Usage:   "network interface to catpure",
				Value:   "all",
			},
			&cli.StringFlag{
				Name:    "s",
				Aliases: []string{"src"},
				Usage:   "source host to capture",
				Value:   "0.0.0.0:1-65536",
			},
			&cli.StringFlag{
				Name:    "d",
				Aliases: []string{"dst"},
				Usage:   "destination host to capture",
				Value:   "0.0.0.0:1-65536",
			},
			&cli.StringFlag{
				Name:    "p",
				Aliases: []string{"packet-type"},
				Usage:   "packet type to capture (tcp/udp/dns/all)",
				Value:   "all",
			},
			&cli.BoolFlag{
				Name:  "4",
				Usage: "IPv4 packet only",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "6",
				Usage: "IPv6 packet only",
				Value: false,
			},
			&cli.StringFlag{
				Name:    "f",
				Aliases: []string{"filter"},
				Usage:   "set BPF Filter like tcpdump",
				Value:   "",
			},
		},
		Action: func(c *cli.Context) error {
			startCapturePacket(c)
			return nil
		},
		CommandNotFound: func(c *cli.Context, command string) {
			fmt.Fprintf(c.App.Writer, "Wrong command %q !\n", command)
		},
	}

	app.Run(os.Args)
}

func initialize() {
	srcMac = ""
	srcIP = ""
	srcPort = ""
	dstMac = ""
	dstIP = ""
	dstPort = ""
}

func startCapturePacket(c *cli.Context) bool {
	nic := c.String("interface")

	useIpv4 := c.Bool("4")
	useIpv6 := c.Bool("6")
	packetType := c.String("p")

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	parser.AddDecodingLayer(&eth)

	if useIpv4 == true {
		parser.AddDecodingLayer(&ip4)
	}

	if useIpv6 == true {
		parser.AddDecodingLayer(&ip6)
	}

	switch packetType {
	case "tcp":
		parser.AddDecodingLayer(&tcp)
	case "udp":
		parser.AddDecodingLayer(&udp)
	case "dns":
		parser.AddDecodingLayer(&udp)
		parser.AddDecodingLayer(&dns)
	case "icmp":
		if useIpv4 == true {
			parser.AddDecodingLayer(&icmpv4)
		}

		if useIpv6 == true {
			parser.AddDecodingLayer(&icmpv6)
		}
	default:
		parser.AddDecodingLayer(&tcp)
		parser.AddDecodingLayer(&udp)
	}

	decoded := []gopacket.LayerType{}

	if nic == "all" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
		}

		for _, device := range devices {
			fmt.Println(device.Name)
		}
		return false
	}

	filter := common.GetBPFFilter(c)

	if handle, err := pcap.OpenLive(nic, 65536, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}

			initialize()

			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeEthernet:
					srcMac = eth.SrcMAC.String()
					dstMac = eth.DstMAC.String()
				case layers.LayerTypeIPv6:
					srcIP = ip6.SrcIP.String()
					dstIP = ip6.DstIP.String()
				case layers.LayerTypeIPv4:
					srcIP = ip4.SrcIP.String()
					dstIP = ip4.DstIP.String()
				case layers.LayerTypeTCP:
					srcPort = tcp.SrcPort.String()
					dstPort = tcp.DstPort.String()

					common.PrintSeperator()
					common.PrintFlow(srcIP, srcPort, dstIP, dstPort)
					common.PrintEtherLayer(nic, srcMac, dstMac)
					common.PrintTcpLayer(tcp.seq)
				case layers.LayerTypeUDP:
					srcPort = udp.SrcPort.String()
					dstPort = udp.DstPort.String()

					common.PrintSeperator()
					common.PrintFlow(srcIP, srcPort, dstIP, dstPort)
					common.PrintEtherLayer(nic, srcMac, dstMac)
				case layers.LayerTypeDNS:
					common.PrintDnsLayer(dns, srcIP, srcPort, dstIP, dstPort)
				}
			}
		}
	}

	return true
}
