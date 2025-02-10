package handler

import (
	"errors"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PayloadModifyFun func([]byte) []byte

const genevePort = 6081

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

	if len(packetLayers) < 4 {
		return nil, errors.New("packet has too few layers")
	}

	return &Packet{
		packet:       packet,
		packetLayers: packetLayers,
	}, nil
}

func (p *Packet) SwapSrcDstIPv4() {
	ipLayer := p.packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("No IPv4 layer found in packet")
		return
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		log.Printf("Failed to convert layer to IPv4")
		return
	}

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
	return len(p.packetLayers) - 2
}

func (p *Packet) insideIPLayerIdx() int {
	return len(p.packetLayers) - 3
}
