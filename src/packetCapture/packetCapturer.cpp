//
// Created by danandla on 4/9/23.
//

#include <packetCapturer.h>

#include <string>
#include <iostream>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/SystemUtils.h>

/**
 * A struct for collecting packet statistics
 */
struct PacketStats {
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    /**
    * Clear all stats
    */
    void clear() {
        ethPacketCount = 0;
        ipv4PacketCount = 0;
        ipv6PacketCount = 0;
        tcpPacketCount = 0;
        udpPacketCount = 0;
        tcpPacketCount = 0;
        dnsPacketCount = 0;
        httpPacketCount = 0;
        sslPacketCount = 0;
    }

    /**
    * C'tor
    */
    PacketStats() { clear(); }

    /**
    * Collect stats from a packet
    */
    void consumePacket(pcpp::Packet &packet) {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    /**
    * Print stats to console
    */
    void printToConsole() {
        std::cout
                << "Ethernet packet count: " << ethPacketCount << std::endl
                << "IPv4 packet count:     " << ipv4PacketCount << std::endl
                << "IPv6 packet count:     " << ipv6PacketCount << std::endl
                << "TCP packet count:      " << tcpPacketCount << std::endl
                << "UDP packet count:      " << udpPacketCount << std::endl
                << "DNS packet count:      " << dnsPacketCount << std::endl
                << "HTTP packet count:     " << httpPacketCount << std::endl
                << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

/**
* A callback function for the async capture which is called each time a packet is captured
*/
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie) {
    // extract the stats object form the cookie
    PacketStats *stats = (PacketStats *) cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);
}

void asyncCapture(pcpp::PcapLiveDevice *dev) {
    PacketStats stats = PacketStats();
    std::cout << std::endl << "Starting async capture..." << std::endl;
    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    dev->startCapture(onPacketArrives, &stats);
    pcpp::multiPlatformSleep(10);
    dev->stopCapture();
    std::cout << "Results:" << std::endl;
    stats.printToConsole();
}

/**
* a callback function for the blocking mode capture which is called each time a packet is captured
*/
static bool onPacketArrivesBlockingMode(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie) {
    // extract the stats object form the cookie
    PacketStats *stats = (PacketStats *) cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);

    // return false means we don't want to stop capturing after this callback
    return false;
}

void syncCapture(pcpp::PcapLiveDevice *dev){
    std::cout << std::endl << "Starting capture in blocking mode..." << std::endl;

    PacketStats stats = PacketStats();
    // clear stats
    stats.clear();

    // start capturing in blocking mode. Give a callback function to call to whenever a packet is captured, the stats object as the cookie and a 10 seconds timeout
    dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

    // thread is blocked until capture is finished

    // capture is finished, print results
        std::cout << "Results:" << std::endl;
    stats.printToConsole();
}



int captureTest(const std::string& interfaceIPAddr) {

    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
    if (dev == NULL) {
        std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
        return 1;
    }

    std::cout
            << "Interface info:" << std::endl
            << "   Interface name:        " << dev->getName() << std::endl
            << "   Interface IP address   "   << interfaceIPAddr << std::endl
            << "   MAC address:           " << dev->getMacAddress() << std::endl
            << "   Default gateway:       " << dev->getDefaultGateway() << std::endl
            << "   Interface MTU:         " << dev->getMtu() << std::endl;

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;

    if (!dev->open()) {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    asyncCapture(dev);
    return 1;
}
