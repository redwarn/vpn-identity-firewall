package handler

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PayloadModifyFun func([]byte) []byte

const genevePort = 6081

const (
	EthernetLayerIdx = 0
	IPv4LayerIdx     = 1
	UDPLayerIdx      = 2
	GeneveLayerIdx   = 3
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

	if len(packetLayers) < 5 {
		return nil, errors.New("packet has too few layers")
	}

	if packetLayers[0].LayerType() != layers.LayerTypeEthernet ||
		packetLayers[1].LayerType() != layers.LayerTypeIPv4 ||
		packetLayers[2].LayerType() != layers.LayerTypeUDP ||
		packetLayers[3].LayerType() != layers.LayerTypeGeneve {
		return nil, errors.New("unexpected layers")
	}

	udp := packetLayers[2].(*layers.UDP)
	if udp.DstPort != genevePort {
		return nil, errors.New("not Geneve packet")
	}

	return &Packet{
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
	for i := len(p.packetLayers) - 1; i >= 0; i-- {
		if layer, ok := p.packetLayers[i].(gopacket.SerializableLayer); ok {
			var opts gopacket.SerializeOptions
			if p.modified && (i == 1 || i == 2) {
				opts = gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}
			} else {
				opts = gopacket.SerializeOptions{
					FixLengths: true,
				}
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
