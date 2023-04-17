//
// Created by danandla on 4/16/23.
//

#ifndef TRAFFICANALYZER_PACKETPARSER_H
#define TRAFFICANALYZER_PACKETPARSER_H

#include <pcapplusplus/Packet.h>

int parseEthLayer(const pcpp::Packet &parsedPacket);
int parseIPv4Layer(const pcpp::Packet &parsedPacket);
int parseTcpLayer(const pcpp::Packet &parsedPacket);
int parseHttpLayer(const pcpp::Packet &parsedPacket);
int parseAll();

#endif //TRAFFICANALYZER_PACKETPARSER_H
