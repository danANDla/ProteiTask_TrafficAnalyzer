//
// Created by danandla on 4/16/23.
//

#include <packetParser.h>
#include <SSLStatsCollector.h>
#include <string>
#include <iostream>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/TablePrinter.h>

int openPcapFile(const std::string &fname, pcpp::RawPacket &rawPacket) {
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(fname);

    if (reader == NULL) {
        std::cerr << "Cannot determine reader for file type" << std::endl;
        return 1;
    }

    if (!reader->open()) {
        std::cerr << "Cannot open " << fname << "for reading" << std::endl;
        return 1;
    }

    // read the first (and only) packet from the file
    if (!reader->getNextPacket(rawPacket)) {
        std::cerr << "Couldn't read the first packet in the file '" << fname << "'" << std::endl;
        return 1;
    }
    reader->close();

    return 0;
}

std::string protocolTypeToString(pcpp::ProtocolType protocolType) {
    switch (protocolType) {
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::TCP:
            return "TCP";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        default:
            return "Unknown";
    }
}

void parsePacket(pcpp::RawPacket packet) {
    pcpp::Packet parsedPacket(&packet);
    for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()) {
        std::cout
                << "Layer type: " << protocolTypeToString(curLayer->getProtocol()) << "; "
                << "Total data: " << curLayer->getDataLen() << " [bytes]; "
                << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "
                << "Layer payload: " << curLayer->getLayerPayloadSize()
                << " [bytes]"
                << std::endl;
    }
}

int parseEthLayer(const pcpp::Packet &parsedPacket) {
    pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL) {
        std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
        return 1;
    }
    std::cout << std::endl
              << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
              << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
              << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType)
              << std::endl;
    return 0;
}

int parseIPv4Layer(const pcpp::Packet &parsedPacket) {
    pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == NULL) {
        std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
        return 1;
    }
    std::cout << std::endl
              << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
              << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
              << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
              << "TTL: " << std::dec << (int) ipLayer->getIPv4Header()->timeToLive << std::endl;
}

std::string tcpFlagsToString(pcpp::TcpLayer *tcpLayer) {
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";
    return result;
}

int parseTcpLayer(const pcpp::Packet &parsedPacket) {
    pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer == NULL) {
        std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;
        return 1;
    }

    std::cout << std::endl
              << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
              << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
              << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl
              << "TCP flags: " << tcpFlagsToString(tcpLayer) << std::endl;
}

std::string httpMethodToString(pcpp::HttpRequestLayer::HttpMethod httpMethod) {
    switch (httpMethod) {
        case pcpp::HttpRequestLayer::HttpGET:
            return "GET";
        case pcpp::HttpRequestLayer::HttpPOST:
            return "POST";
        default:
            return "Other";
    }
}

int parseHttpLayer(const pcpp::Packet &parsedPacket) {
    pcpp::HttpRequestLayer *httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer == NULL) {
        return 1;
    }
    std::cout << std::endl
              << "HTTP method: " << httpMethodToString(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
              << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl
              << "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
              << "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue()
              << std::endl
              << "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue()
              << std::endl;

    httpRequestLayer->getPrevLayer()->getProtocol();

    std::cout << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;
    return 0;
}

int parseSSLLayer(const pcpp::Packet &parsedPacket) {
    pcpp::SSLApplicationDataLayer *sslLayer = parsedPacket.getLayerOfType<pcpp::SSLApplicationDataLayer>();
    if (sslLayer == NULL) {
        return 1;
    }
    std::cout << sslLayer->getEncryptedData()
              << sslLayer->getData() << std::endl
              << sslLayer->getProtocol() << std::endl
              << std::endl;

    return 0;
}

bool stringCountComparer(const std::pair<std::string, int> &first, const std::pair<std::string, int> &second) {
    if (first.second == second.second) {
        return first.first > second.first;
    }
    return first.second > second.second;
}

void printServerNames(ClientHelloStats &clientHelloStatsCollector) {
    std::vector<std::string> columnNames;
    columnNames.push_back("Hostname");
    columnNames.push_back("Count");
    std::vector<int> columnsWidths;
    columnsWidths.push_back(40);
    columnsWidths.push_back(5);
    pcpp::TablePrinter printer(columnNames, columnsWidths);

    std::vector<std::pair<std::string, int> > map2vec(clientHelloStatsCollector.serverNameCount.begin(),
                                                      clientHelloStatsCollector.serverNameCount.end());
    std::sort(map2vec.begin(), map2vec.end(), &stringCountComparer);

    // go over all items (names + count) in the sorted vector and print them
    for (std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
         iter != map2vec.end();
         iter++) {
        std::stringstream values;
        values << iter->first << "|" << iter->second;
        printer.printRow(values.str(), '|');
    }
}

bool isUsefulPacket(const pcpp::Packet &parsedPacket) {
    return parsedPacket.isPacketOfType(pcpp::Ethernet) ||
           parsedPacket.isPacketOfType(pcpp::IPv4) ||
           parsedPacket.isPacketOfType(pcpp::TCP) ||
           parsedPacket.isPacketOfType(pcpp::HTTP) ||
           parsedPacket.isPacketOfType(pcpp::SSL);
}

int parseAll() {
    pcpp::RawPacket rpacket;

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("out.pcap");

    if (reader == NULL) {
        std::cerr << "Cannot determine reader for file type" << std::endl;
        return 1;
    }

    if (!reader->open()) {
        std::cerr << "Cannot open out.pcap for reading" << std::endl;
        return 1;
    }

    pcpp::RawPacket rawPacket;
    SSLStatsCollector collector;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
//        if(isUsefulPacket(parsedPacket)) printf("\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n");
//        if (parsedPacket.isPacketOfType(pcpp::Ethernet)) parseEthLayer(parsedPacket);
//        if (parsedPacket.isPacketOfType(pcpp::IPv4)) parseIPv4Layer(parsedPacket);
//        if (parsedPacket.isPacketOfType(pcpp::TCP)) parseTcpLayer(parsedPacket);
        if (parsedPacket.isPacketOfType(pcpp::HTTP)) parseHttpLayer(parsedPacket);
        if (parsedPacket.isPacketOfType(pcpp::SSL)) {
            collector.collectStats(&parsedPacket);
        }
//        if(isUsefulPacket(parsedPacket)) printf("\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n");
    }
    reader->close();

    printServerNames(collector.getClientHelloStats());

    return 0;
}