/*
 * PacketAnalyzer.c
 *
 *  Created on: 9 de set de 2018
 *      Author: rodrigo
 */

#include <string.h>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include "PacketAnalyzer.h"
#include <list>
#include <algorithm>

using namespace std;

typedef struct pcktHeader
{
  ether_header header;

  bool operator==(const pcktHeader& m) const {
    return ((!memcmp(m.header.ether_dhost, header.ether_dhost, ETH_ALEN))
        && (!memcmp(m.header.ether_shost, header.ether_shost, ETH_ALEN)));
  };
}pckanPcktHeader_t;

static std::list <pckanPcktHeader_t> MACAddrList;

void _pckanlz_PacketReceivedCallback(u_char *, const struct pcap_pkthdr *, const u_char * pcPacket)
{
  pckanPcktHeader_t * PacketHeader;
  PacketHeader = ( pckanPcktHeader_t *) pcPacket;

  if(find(MACAddrList.begin(), MACAddrList.end(), *PacketHeader) == MACAddrList.end())
  {
    MACAddrList.push_back(*PacketHeader);
    cout << "ListSize = " << MACAddrList.size() << endl;

    cout << "MAC origin: "<< ether_ntoa( (const struct ether_addr *)PacketHeader->header.ether_shost) << endl;
    cout << "MAC destiny: "<< ether_ntoa( (const struct ether_addr *)PacketHeader->header.ether_dhost) << endl;
  }
}
PacketAnalyzer::PacketAnalyzer(void)
{

}

pcap_handler PacketAnalyzer::PckAnlz_GetPacketReceivedCallback(void)
{
  return _pckanlz_PacketReceivedCallback;
}
