package handler

import (
	"errors"
	"fmt"

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
	packet       gopacket.Packet
	packetLayers []gopacket.Layer
}

func NewPacket(packet gopacket.Packet) (*Packet, error) {
	if packet == nil {
		return nil, errors.New("invalid packet")
	}

	packetLayers := packet.Layers()

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
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	for i := len(p.packetLayers) - 1; i >= 0; i-- {
		if layer, ok := p.packetLayers[i].(gopacket.SerializableLayer); ok {
			opts := gopacket.SerializeOptions{FixLengths: true}
			err := layer.SerializeTo(buf, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize layer %v: %w", layer.LayerType(), err)
			}
			buf.PushLayer(layer.LayerType())
		} else if layer, ok := p.packetLayers[i].(*layers.Geneve); ok {
			bytes, err := buf.PrependBytes(len(layer.Contents))
			if err != nil {
				return nil, fmt.Errorf("failed to prepend geneve bytes: %w", err)
			}
			copy(bytes, layer.Contents)
		} else {
			return nil, fmt.Errorf("layer of unknown type: %v", p.packetLayers[i].LayerType())
		}
	}
	return buf.Bytes(), nil
}
