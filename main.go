package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
)

func main() {
	f, err := os.Create("en0.pcap")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}

	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 37008"); err != nil { 
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			incapsulatedPacket := gopacket.NewPacket(packet.ApplicationLayer().Payload()[5:], layers.LayerTypeEthernet, gopacket.Default)
			incapsulatedPacket.Metadata().CaptureInfo.Length = len(incapsulatedPacket.Data())
			incapsulatedPacket.Metadata().CaptureInfo.CaptureLength = len(incapsulatedPacket.Data())
			if err := pcapw.WritePacket(incapsulatedPacket.Metadata().CaptureInfo, incapsulatedPacket.Data()); err != nil {
				panic(err)
			}
		}
	}
}
