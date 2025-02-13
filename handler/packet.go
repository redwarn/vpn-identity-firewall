package handler

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PayloadModifyFun func([]byte) []byte

const (
	genevePort        = 6081
	ipLayerIdx        = 3
	transportLayerIdx = 4
)

type Packet struct {
	modified     bool
	packet       gopacket.Packet
	packetLayers []gopacket.Layer
}

func NewPacket(data []byte) (*Packet, error) {
	p := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if p == nil {
		return nil, errors.New("invalid packet")
	}

	packetLayers := p.Layers()

	if len(packetLayers) < 5 {
		return nil, errors.New("packet has too few layers")
	}

	if packetLayers[0].LayerType() != layers.LayerTypeIPv4 || packetLayers[1].LayerType() != layers.LayerTypeUDP || packetLayers[2].LayerType() != layers.LayerTypeGeneve {
		return nil, errors.New("unexpected layers")
	}

	udp := packetLayers[1].(*layers.UDP)
	if udp.DstPort != genevePort {
		return nil, errors.New("not Geneve packet")
	}

	packet := &Packet{
		packet:       p,
		packetLayers: p.Layers(),
	}

	return packet, nil
}

func (p Packet) String() string {
	return p.packet.String()
}

func (p *Packet) SwapSrcDstIPv4() {
	ip := p.packetLayers[0].(*layers.IPv4)
	dst := ip.DstIP
	ip.DstIP = ip.SrcIP
	ip.SrcIP = dst
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	for i := len(p.packetLayers) - 1; i >= 0; i-- {
		if layer, ok := p.packetLayers[i].(gopacket.SerializableLayer); ok {
			var opts gopacket.SerializeOptions
			if p.modified && (i == p.insideUDPLayerIdx() || i == p.insideIPLayerIdx()) {
				opts = gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			} else {
				opts = gopacket.SerializeOptions{FixLengths: true}
			}
			err := layer.SerializeTo(buf, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize layer: %w", err)
			}
			buf.PushLayer(layer.LayerType())
		} else if layer, ok := p.packetLayers[i].(*layers.Geneve); ok {
			bytes, err := buf.PrependBytes(len(layer.Contents))
			if err != nil {
				return nil, fmt.Errorf("failed to prepend geneve bytes: %v", err)
			}
			copy(bytes, layer.Contents)
		} else {
			return nil, fmt.Errorf("layer of unknown type: %v", p.packetLayers[i].LayerType())
		}
	}
	return buf.Bytes(), nil
}

func (p *Packet) insideUDPLayerIdx() int {
	return len(p.packetLayers) - 2
}

func (p *Packet) insideIPLayerIdx() int {
	return len(p.packetLayers) - 3
}

func (p *Packet) GetInnerAddresses() (srcIP, dstIP string) {
	if innerIP, ok := p.packetLayers[ipLayerIdx].(*layers.IPv4); ok {
		return innerIP.SrcIP.String(), innerIP.DstIP.String()
	}
	return "", ""
	// if innerTCP, ok := p.packetLayers[transportLayerIdx].(*layers.TCP); ok {
	// 	return innerIP.SrcIP.String(), innerIP.DstIP.String(), uint16(innerTCP.SrcPort), uint16(innerTCP.DstPort), nil
	// }
	// if innerUDP, ok := p.packetLayers[transportLayerIdx].(*layers.UDP); ok {
	// 	return innerIP.SrcIP.String(), innerIP.DstIP.String(), uint16(innerUDP.SrcPort), uint16(innerUDP.DstPort), nil
	// }

	// return "", "", 0, 0, errors.New("invalid inner transport layer (neither TCP nor UDP)")
}
