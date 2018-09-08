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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "PCAPLib.h"

using namespace std;

pcap_if_t * psNetStruct;
char errbuf[PCAP_ERRBUF_SIZE];

void _pcapPrintAvailableInterfaces( pcap_if_t * psInterface )
{
  for(int DeviceCounter = 0; ;DeviceCounter++)
  {
    cout << DeviceCounter << ": " << psInterface->name << endl;
    if(psInterface->next != NULL)
    {
      psInterface = psInterface->next;
    }
    else
    {
      break;
    }
  }
}

int _pcapRequestInterfaceFromUser( pcap_if_t * psInterface )
{
  int SelectedInterface;

  cout << "Please, select the interface you want to read:" << endl;

  _pcapPrintAvailableInterfaces( psInterface );

  cin >> SelectedInterface;

  return SelectedInterface;
}

pcap_if_t * _pcapGetInterfacePerIndex(int InterfaceIndex, pcap_if_t * psInterface )
{
  for( int DeviceCounter = 0; DeviceCounter < InterfaceIndex ;DeviceCounter++)
  {
    if(psInterface->next != NULL)
    {
      psInterface = psInterface->next;
    }
    else
    {
      return NULL;
    }
  }
  return psInterface;
}

void _pcapPrintNetworkAddr(bpf_u_int32 Addr)
{
  char * net;
  struct in_addr addr;

  addr.s_addr = Addr;
  if((net = inet_ntoa( addr ))== NULL)
  {
    perror ( "inet_ntoa" );
  }
  cout << net << endl;
}
void _pcapPrintInterfaceInfo( pcap_if_t * psInterface )
{
  bpf_u_int32 NetAddr;
  bpf_u_int32 NetMask;


  if(psInterface != NULL)
  {
    if( pcap_lookupnet(psInterface->name, &NetAddr, &NetMask, errbuf) == -1)
    {
      cout << errbuf << endl;
    }
    else
    {
      cout << "-----------------------------------" << endl;
      cout << "NetworkAddr : ";
      _pcapPrintNetworkAddr( NetAddr );
      cout << "NetworkMask : ";
      _pcapPrintNetworkAddr( NetMask );
      cout << "-----------------------------------" << endl;

    }
  }
}

PCAPLib::PCAPLib( void )
{
  psNetStruct = NULL;
  cout << pcap_lib_version() << endl;
  return;
}

void PCAPLib::PCAPInit( void )
{
  pcap_findalldevs(&psNetStruct, errbuf);

  pcap_if_t * psInitialNetStruct = psNetStruct;

  if(psInitialNetStruct != NULL)
  {
    int SelectedInterface;

    SelectedInterface = _pcapRequestInterfaceFromUser(psNetStruct);

    psNetStruct = _pcapGetInterfacePerIndex(SelectedInterface, psNetStruct );
    if(psNetStruct != NULL)
    {
      cout << "Interface Selected --> " << psNetStruct->name << endl;
      _pcapPrintInterfaceInfo( psNetStruct );
    }
    else
    {
      cout << "Interface Selection ERROR!" << endl;
    }
  }
};

void PCAPLib::PCAPCaptureStart( void )
{
  pcap_t *psPcapDescriptor = NULL;
  const u_char * packet;

  if(psNetStruct != NULL)
  {
    psPcapDescriptor = pcap_open_live(psNetStruct->name, BUFSIZ,1,100, errbuf);
  }

  if(psPcapDescriptor != NULL)
  {
    pcap_pkthdr Packet;
    while(1)
    {
      packet = pcap_next (psPcapDescriptor, &Packet);
      if(Packet.len >0)
      {
        cout << endl << Packet.ts.tv_sec << ":" << Packet.ts.tv_usec << " " << Packet.caplen << " Packet size: " << Packet.len << endl;

        for(bpf_u_int32 i=0; i< Packet.len ;++i)
            cout << setw(2) << setfill('0') << (int)packet[i];
      }
    }
  }
  cout << errbuf << endl;
  return;
};
