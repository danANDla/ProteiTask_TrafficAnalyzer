//
// Created by danandla on 4/6/23.
//

//#include "../../include/packetReader.h"

#include <packetReader.h>

#include <iostream>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>

int readingTest() {
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open()) {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket)) {
        std::cerr << "Couldn't read the first packet in the file" << std::endl;
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // print source and dest IPs
        std::cout
                << "Source IP is '" << srcIP << "'; "
                << "Dest IP is '" << destIP << "'"
                << std::endl;
    }

    // close the file
    reader.close();

    return 0;
}