package handler

import (
	"errors"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PayloadModifyFun func([]byte) []byte

const (
	ethLayer            = 1
	ipLayerIdx          = 2
	updLayerIdx         = 3
	innerIPLayerIdx     = 4
	innerTransportLayer = 5
	applicationLayer    = 6
)

type Packet struct {
	modified     bool
	packet       gopacket.Packet
	packetLayers []gopacket.Layer
}

func NewPacket(packet gopacket.Packet) (*Packet, error) {
	if packet == nil {
		return nil, errors.New("invalid packet")
	}

	packetLayers := packet.Layers()

	return &Packet{
		modified:     true,
		packet:       packet,
		packetLayers: packetLayers,
	}, nil
}

func (p Packet) String() string {
	return p.packet.String()
}

func (p *Packet) SwapSrcDstIPv4() {
	ip := p.packetLayers[1].(*layers.IPv4)
	dst := ip.DstIP
	ip.DstIP = ip.SrcIP
	ip.SrcIP = dst
	p.modified = true
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	fmt.Println(len(p.packetLayers))
	for i := len(p.packetLayers) - 1; i >= 0; i-- {
		fmt.Println(p.packetLayers[i].LayerType())
		if layer, ok := p.packetLayers[i].(gopacket.SerializableLayer); ok {
			var opts gopacket.SerializeOptions
			if p.modified && i == p.insideUDPLayerIdx() {
				opts = gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			} else {
				opts = gopacket.SerializeOptions{FixLengths: true}
			}
			fmt.Print(string(buf.Bytes()))
			err := layer.SerializeTo(buf, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize layer: %w", err)
			}
			buf.PushLayer(layer.LayerType())
		} else if layer, ok := p.packetLayers[i].(*layers.Geneve); ok {
			bytes, err := buf.PrependBytes(len(layer.Contents))
			if err != nil {
				log.Printf("failed to prepend geneve bytes: %v", err)
			}
			copy(bytes, layer.Contents)
		} else {
			return nil, fmt.Errorf("layer of unknown type: %v", p.packetLayers[i].LayerType())
		}
	}
	return buf.Bytes(), nil
}

func (p *Packet) insideUDPLayerIdx() int {
	return len(p.packetLayers) - 4
}

// - Layer 1 (14 bytes) = Ethernet	{Contents=[..14..] Payload=[..128..] SrcMAC=06:30:ef:83:93:87 DstMAC=06:36:45:f1:49:d7 EthernetType=IPv4 Length=0}
// - Layer 2 (20 bytes) = IPv4	{Contents=[..20..] Payload=[..108..] Version=4 IHL=5 TOS=0 Length=128 Id=0 Flags= FragOffset=0 TTL=255 Protocol=UDP Checksum=41471 SrcIP=10.126.130.56 DstIP=10.126.130.57 Options=[] Padding=[]}
// - Layer 3 (08 bytes) = UDP	{Contents=[..8..] Payload=[..100..] SrcPort=62039 DstPort=6081(geneve) Length=108 Checksum=52104}
// - Layer 4 (40 bytes) = Geneve	{Contents=[..40..] Payload=[..60..] Version=0 OptionsLength=32 OAMPacket=false CriticalOption=false Protocol=IPv4 VNI=0 Options=[{Class=264 Type=1 Flags=0 Length=12 Data=[..8..]}, {Class=264 Type=2 Flags=0 Length=12 Data=[..8..]}, {Class=264 Type=3 Flags=0 Length=8 Data=[140, 190, 228, 157]}]}
// - Layer 5 (20 bytes) = IPv4	{Contents=[..20..] Payload=[..40..] Version=4 IHL=5 TOS=0 Length=60 Id=22202 Flags=DF FragOffset=0 TTL=62 Protocol=TCP Checksum=27388 SrcIP=172.21.100.37 DstIP=10.0.96.203 Options=[] Padding=[]}
// - Layer 6 (40 bytes) = TCP	{Contents=[..40..] Payload=[] SrcPort=56436 DstPort=5201(targus-getdata1) Seq=227517945 Ack=0 DataOffset=10 FIN=false SYN=true RST=false PSH=false ACK=false URG=false ECE=false CWR=false NS=false Window=62727 Checksum=19022 Urgent=0 Options=[..5..] Padding=[]}
// 2025/02/12 14:27:45 failed to serialize packet: failed to serialize layer: TCP/IP layer 4 checksum cannot be computed without network layer... call SetNetworkLayerForChecksum to set which layer to use
