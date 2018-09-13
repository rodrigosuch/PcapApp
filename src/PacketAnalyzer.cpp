/*
 * PacketAnalyzer.c
 *
 *  Created on: 9 de set de 2018
 *      Author: rodrigo
 */


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

using namespace std;

void _pckanlz_PacketReceivedCallback(u_char *, const struct pcap_pkthdr *, const u_char * pcPacket)
{
  struct ether_header * eptr;

  eptr = ( struct ether_header *) pcPacket;


  cout << "MAC origin: "<< ether_ntoa( (const struct ether_addr *)eptr->ether_shost) << endl;
  cout << "MAC destiny: "<< ether_ntoa( (const struct ether_addr *)eptr->ether_dhost) << endl;


}

pcap_handler PacketAnalyzer::PckAnlz_GetPacketReceivedCallback(void)
{
  return _pckanlz_PacketReceivedCallback;
}
