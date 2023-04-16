//
// Created by danandla on 4/16/23.
//

#include <deviceManager.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>

int getDevByName(const std::string& devName, std::string &ip){
    static char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
        printf("%s\n", errbuf);
        return 1;
    }

    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        if(std::strcmp(d->name, devName.c_str()) == 0){
            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
                if(a->addr->sa_family == AF_INET){
                    ip = std::string(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
                }
            }
            return 0;
        }
    }

    pcap_freealldevs(alldevs);
    printf("Device with this name was not found\n");
    return 1;
}