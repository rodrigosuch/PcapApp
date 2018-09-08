/*
 * PCAPLib.cpp
 *
 *  Created on: 8 de set de 2018
 *      Author: rodrigo
 */

#include <iostream>
#include <pcap.h>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#include "PCAPLib.h"

using namespace std;

PCAPLib::PCAPLib( void )
{
  psNetStruct = NULL;
  cout << pcap_lib_version() << endl;
  return;
}

void PCAPLib::PCAPInit( void )
{
  pcap_findalldevs(&psNetStruct, errbuf);
  if(psNetStruct != NULL)
  {
    cout << "Please, select the interface you want to read:" << endl;
    for(int DeviceCounter = 0; ;DeviceCounter++)
    {
      cout << DeviceCounter << ": " << psNetStruct->name << endl;
      if(psNetStruct->next != NULL)
      {
        psNetStruct = psNetStruct->next;
      }
      else
      {
        break;
      }
    }
  }
};

void PCAPLib::PCAPStart( void )
{
  pcap_t *psPcapDescriptor = NULL;
  const u_char * packet;
  psPcapDescriptor = pcap_open_live("wlan0",BUFSIZ,1,100, errbuf);

  if(psPcapDescriptor != NULL)
  {
    pcap_pkthdr Packet;
    while(1)
    {
      packet = pcap_next (psPcapDescriptor, &Packet);
      if(Packet.len >0)
      {
        cout << Packet.ts.tv_sec << ":" << Packet.ts.tv_usec << " " << Packet.caplen << " Packet size: " << Packet.len << endl;

        for(bpf_u_int32 i=0; i< Packet.len ;++i)
            cout << setw(2) << setfill('0') << (int)packet[i];
      }
    }
  }
  cout << errbuf << endl;
  return;
};
