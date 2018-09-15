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
#include <netinet/ip.h>
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
        && (!memcmp(m.header.ether_shost, header.ether_shost, ETH_ALEN)))
        && (m.header.ether_type == header.ether_type);
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
    cout << endl << MACAddrList.size() << "------------------------------------------" << endl;
    cout << "MAC origin: "<< ether_ntoa( (const struct ether_addr *)PacketHeader->header.ether_shost) << endl;
    cout << "MAC destiny: "<< ether_ntoa( (const struct ether_addr *)PacketHeader->header.ether_dhost) << endl;
  }
  switch (PacketHeader->header.ether_type)
  {
    case ETHERTYPE_IP:
      cout << "IP Packet! " << endl;
    break;

    case ETHERTYPE_ARP:
      cout << "ARP Packet! " << endl;
    break;

    case ETHERTYPE_PUP:
    case ETHERTYPE_SPRITE:/* Sprite */
    case ETHERTYPE_REVARP:/* Reverse ARP */
    case ETHERTYPE_AT:    /* AppleTalk protocol */
    case ETHERTYPE_AARP:  /* AppleTalk ARP */
    case ETHERTYPE_VLAN:  /* IEEE 802.1Q VLAN tagging */
    case ETHERTYPE_IPX:   /* IPX */
    case ETHERTYPE_IPV6:  /* IP protocol version 6 */
    case ETHERTYPE_LOOPBACK:/* used to test interfaces */
      cout << "Packet type not treated" << PacketHeader->header.ether_type << endl;
    break;

    default:
//      cout << "Packet type is not treated: "<< PacketHeader->header.ether_type << endl;
    break;
  }
  struct ip * ipc;
  ipc = (struct ip *)(pcPacket + sizeof( struct ether_header ));
  cout << ipc->ip_id;

  switch(ipc->ip_p)
  {
    case 1:
      cout << " ICMP";
    break;

    case 6:
      cout << " TCP";
    break;

    case 17:
      cout << " UDP";
    break;

    default:
      cout << " " << (int)ipc->ip_p;
    break;
  }
  cout << ": " << inet_ntoa ( ipc->ip_src );
  cout << " >> " << inet_ntoa ( ipc->ip_dst) << endl;
}

PacketAnalyzer::PacketAnalyzer(void)
{

}

pcap_handler PacketAnalyzer::PckAnlz_GetPacketReceivedCallback(void)
{
  return _pckanlz_PacketReceivedCallback;
}
