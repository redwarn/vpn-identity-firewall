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
	// 将数据包分为外部和内部两部分
	var outerLayers, innerLayers []gopacket.Layer
	geneveFound := false

	for _, layer := range p.packetLayers {
		if !geneveFound {
			if _, isGeneve := layer.(*layers.Geneve); isGeneve {
				geneveFound = true
			}
			outerLayers = append(outerLayers, layer)
		} else {
			innerLayers = append(innerLayers, layer)
		}
	}

	// 先序列化内部包
	innerBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// 找到内部的 IPv4 和 TCP 层
	var innerIPv4 *layers.IPv4
	var tcp *layers.TCP
	for _, layer := range innerLayers {
		switch l := layer.(type) {
		case *layers.IPv4:
			innerIPv4 = l
		case *layers.TCP:
			tcp = l
		}
	}

	// 设置内部 TCP 的校验和依赖
	if tcp != nil && innerIPv4 != nil {
		tcp.SetNetworkLayerForChecksum(innerIPv4)
	}

	// 序列化内部包（从后向前）
	for i := len(innerLayers) - 1; i >= 0; i-- {
		if layer, ok := innerLayers[i].(gopacket.SerializableLayer); ok {
			err := layer.SerializeTo(innerBuf, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize inner layer: %w", err)
			}
		}
	}

	// 准备外部包的序列化
	outerBuf := gopacket.NewSerializeBuffer()

	// 找到外部的 IPv4 和 UDP 层
	var outerIPv4 *layers.IPv4
	var outerUDP *layers.UDP
	for _, layer := range outerLayers {
		switch l := layer.(type) {
		case *layers.IPv4:
			outerIPv4 = l
		case *layers.UDP:
			outerUDP = l
		}
	}

	// 设置外部 UDP 的校验和依赖
	if outerUDP != nil && outerIPv4 != nil {
		outerUDP.SetNetworkLayerForChecksum(outerIPv4)
	}

	// 序列化外部包（从后向前）
	for i := len(outerLayers) - 1; i >= 0; i-- {
		if layer, ok := outerLayers[i].(gopacket.SerializableLayer); ok {
			err := layer.SerializeTo(outerBuf, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize outer layer: %w", err)
			}
		} else if layer, ok := outerLayers[i].(*layers.Geneve); ok {
			// 处理 Geneve 层
			bytes, err := outerBuf.PrependBytes(len(layer.Contents))
			if err != nil {
				return nil, fmt.Errorf("failed to prepend geneve bytes: %v", err)
			}
			copy(bytes, layer.Contents)

			// 添加内部包的内容
			innerBytes := innerBuf.Bytes()
			payload, err := outerBuf.PrependBytes(len(innerBytes))
			if err != nil {
				return nil, fmt.Errorf("failed to prepend inner packet: %v", err)
			}
			copy(payload, innerBytes)
		}
	}

	return outerBuf.Bytes(), nil
}
