package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/urfave/cli/v2"
)

type DnsMsg struct {
	Time            string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func GetBPFFilter(c *cli.Context) string {
	inputFilter := c.String("filter")
	src := c.String("src")
	dst := c.String("dst")

	filter := ""

	fmt.Println(src)
	fmt.Println(dst)

	srcTmp := strings.Split(src, ":")
	srcIP := srcTmp[0]
	srcPORT := srcTmp[1]

	dstTmp := strings.Split(dst, ":")
	dstIP := dstTmp[0]
	dstPORT := dstTmp[1]

	srcFilter := ""

	if srcIP != "0.0.0.0" {
		srcFilter = "src host " + srcIP
	}

	if srcPORT != "1-65536" {
		if srcFilter != "" {
			srcFilter += " and "
		}

		srcFilter += "src port " + srcPORT
	}

	dstFilter := ""

	if dstIP != "0.0.0.0" {
		dstFilter = "dst host " + dstIP
	}

	if dstPORT != "1-65536" {
		if dstFilter != "" {
			dstFilter += " and "
		}

		dstFilter += "dst port " + dstPORT
	}

	if srcFilter != "" {
		filter += srcFilter
	}
	if dstFilter != "" {
		if filter != "" {
			filter += " and "
		}

		filter += dstFilter
	}

	if inputFilter != "" {
		if filter != "" {
			filter += " and "
		}

		filter += inputFilter
	}

	return filter
}

func PrintSeperator() {
	fmt.Println("    -------------------")
}

func PrintFlow(srcIP string, srcPort string, dstIP string, dstPort string) {
	fmt.Println("    Flow ", srcIP, ":", srcPort, " --> ", dstIP, ":", dstPort)
}

func PrintEtherLayer(nic string, srcMac string, dstMac string) {
	fmt.Println("    Device ", nic)
	fmt.Println("    Source Mac ", srcMac)
	fmt.Println("    Destionation Mac ", dstMac)
}

func PrintDnsLayer(dns layers.DNS, srcIP string, srcPort string, dstIP string, dstPort string) {
	dnsOpCode := int(dns.OpCode)
	dnsResponseCode := int(dns.ResponseCode)
	dnsANCount := int(dns.ANCount)

	// if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
	fmt.Println("    DNS Record Detected")

	for _, dnsQuestion := range dns.Questions {

		t := time.Now()
		timestamp := t.String()

		// Add a document to the index
		d := DnsMsg{Time: timestamp, SourceIP: srcIP,
			DestinationIP:   dstIP,
			DnsQuery:        string(dnsQuestion.Name),
			DnsOpCode:       strconv.Itoa(dnsOpCode),
			DnsResponseCode: strconv.Itoa(dnsResponseCode),
			NumberOfAnswers: strconv.Itoa(dnsANCount)}

		fmt.Println("    DNS Time: ", d.Time)
		fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
		fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
		fmt.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
		fmt.Println("    DNS Question: ", string(dnsQuestion.Name), "(", strings.TrimSpace(string(dnsQuestion.Type)), ")")
		fmt.Println("    DNS Endpoints: ", srcIP, dstIP)

		if dnsANCount > 0 {
			for _, dnsAnswer := range dns.Answers {
				d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
				if dnsAnswer.IP.String() != "<nil>" {
					d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
				}
			}
			fmt.Println("    DNS Answer: ", strings.Join(d.DnsAnswer, " "))
		}
	}
}

func PrintTcpLayer(seq uint32) {
	fmt.Println("    Seq Number ", strconv.FormatUint(uint64(seq), 10))
}

func PrintPayload(payload gopacket.Payload) {
	// fmt.Println("Header : " + string(payload.LayerContents()))
	// fmt.Println("Body : " + string(payload.LayerPayload()))
	fmt.Println(payload.GoString())
}
