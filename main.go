package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	fInterface   = flag.String("i", "eth0", "interface to listen")
	fSnapLen     = flag.Int("s", 1600, "maximum size in byte of a packet")
	fPromiscuous = flag.Bool("p", false, "promiscuous mode")
	fExpression  = flag.String("e", "", "expression, example: tcp and port 80")
	fBufferPkt   = flag.Int("b", 10000, "count of packets in buffer")
	fDoubleMode  = flag.String("m", "", "mode: ttl / eb (evil bit)")
	fTtl         = flag.Uint("ttl", 164, "ttl value, ttl mode only")

	mTtl = false
	mEB  = false

	sendCh chan gopacket.Packet
	handle *pcap.Handle
)

func main() {
	flag.Parse()

	if *fDoubleMode == "ttl" {
		mTtl = true
	} else if *fDoubleMode == "eb" {
		mEB = true
	} else {
		log.Fatal("mode is not specified")
	}

	var err error
	handle, err = pcap.OpenLive(*fInterface, int32(*fSnapLen), *fPromiscuous, 30*time.Second)
	if err != nil {
		log.Fatal("open interface error:", err)
	}
	defer handle.Close()

	sendCh = make(chan gopacket.Packet, *fBufferPkt)
	go sender()

	err = handle.SetBPFFilter(*fExpression)
	if err != nil {
		log.Fatal("set filter error:", err)
	}

	log.Println("running...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}

func handlePacket(packet gopacket.Packet) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return
	}
	ip4, _ := ip4Layer.(*layers.IPv4)

	if mTtl {
		if ip4.TTL == uint8(*fTtl) {
			return
		}
		ip4.TTL = uint8(*fTtl)
	} else if mEB {
		if ip4.Flags&layers.IPv4EvilBit > 0 {
			return
		}
		ip4.Flags |= layers.IPv4EvilBit
	} else {
		return
	}

	sendCh <- packet
}

func sender() {
	opts := gopacket.SerializeOptions{}

	for pkt := range sendCh {
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializePacket(buf, opts, pkt)
		if err != nil {
			log.Println("serialize error:", err)
			continue
		}

		b := buf.Bytes()
		err = handle.WritePacketData(b)
		if err != nil {
			log.Println("send error:", err)
		}
	}
}
