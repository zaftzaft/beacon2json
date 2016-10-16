package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

type Beacon struct {
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"`
	SSID      string `json:"ssid"`
	Freq      uint   `json:"freq"`
	Signal    int8   `json:"signal"`
	Interval  uint16 `json:"interval"`
}

type Beacons []Beacon

func main() {
	var filename string
	flag.StringVar(&filename, "r", "", "pcap file")

	flag.Parse()

	if filename == "" {
		log.Fatal("[Error] Use -r flag")
	}

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal("[Error] pcap OpenOffline err", err)
	}
	defer handle.Close()

	var beacons Beacons

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
		if beaconLayer == nil {
			continue
		}

		mgmt := beaconLayer.(*layers.Dot11MgmtBeacon)
		radiotap := packet.Layer(layers.LayerTypeRadioTap)
		rt := radiotap.(*layers.RadioTap)
		elm := packet.Layer(layers.LayerTypeDot11InformationElement).(*layers.Dot11InformationElement)
		srcAddr := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11).Address2

		beacons = append(beacons, Beacon{
			Timestamp: packet.Metadata().Timestamp.UnixNano(),
			Source:    srcAddr.String(),
			SSID:      string(elm.Info),
			Freq:      uint(rt.ChannelFrequency),
			Signal:    rt.DBMAntennaSignal,
			Interval:  mgmt.Interval,
		})
	}

	jsonByte, err := json.Marshal(beacons)
	if err != nil {
		log.Fatal("[Error] JSON parse error", err)
	}

	fmt.Println(string(jsonByte))

}
