#include <iostream>

#include <packetReader.h>
#include <packetCapturer.h>
#include <deviceManager.h>
#include <packetParser.h>


int main(int argc, char** argv) {
    if(argc < 2) {
        printf("expected device name as argument\n");
        return 1;
    } else if (argc > 3){
        printf("expected 1 argument\n");
        return 1;
    }
    std::string devName;
    devName = argv[1];
    std::string ip;
    if(getDevByName(devName, ip)) return 1;
    captureTest(ip);
    parseAll();
    return 0;
}
