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
#include <netinet/ether.h>
#include <sys/socket.h>
#include "PCAPLib.h"

using namespace std;

string FileName;
pcap_if_t * psNetStruct;
char errbuf[PCAP_ERRBUF_SIZE];

void _pcapPrintAvailableInterfaces( void )
{
  pcap_if_t * psLocalNetStruct;

  pcap_findalldevs(&psLocalNetStruct, errbuf);
  psNetStruct = psLocalNetStruct;

  for(int DeviceCounter = 0; ;DeviceCounter++)
  {
    cout << DeviceCounter << ": " << psLocalNetStruct->name << endl;
    if(psLocalNetStruct->next != NULL)
    {
      psLocalNetStruct = psLocalNetStruct->next;
    }
    else
    {
      break;
    }
  }
}

bool _pcapRequestOnlineOffline( void )
{
  bool SelectedOption;

  cout << "Do you want an online or offline parsing? \r\n(0)Online\r\n(1)Offline" << endl;
  cin >> SelectedOption;

  return SelectedOption;
}

void _pcapRequestFileToParse( string * FileName )
{
  cout << "Please enter the file name you want to parse" << endl;
  cin >> *FileName;
}

int _pcapRequestInterfaceFromUser( void )
{
  int SelectedInterface;

  cout << "Please, select the interface you want to read:" << endl;

  _pcapPrintAvailableInterfaces();

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
      cout << "Interface Selected --> " << psNetStruct->name << endl;
      cout << "-----------------------------------" << endl;
      cout << "NetworkAddr : ";
      _pcapPrintNetworkAddr( NetAddr );
      cout << "NetworkMask : ";
      _pcapPrintNetworkAddr( NetMask );
      cout << "-----------------------------------" << endl;

    }
  }
  else
  {
    cout << "Interface Selection ERROR!" << endl;
  }
}

void _pcapReadInCallback( pcap_t * psPcapDescriptor, pcap_handler pfCallback )
{
  pcap_loop ( psPcapDescriptor, -1, pfCallback, NULL );
}

void _pcapReadInLoop( pcap_t * psPcapDescriptor )
{
  pcap_pkthdr Packet;
  const u_char * packet;

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

PCAPLib::PCAPLib( void )
{
  psNetStruct = NULL;
  cout << pcap_lib_version() << endl;
  return;
}

void PCAPLib::PCAPInit( void )
{

    // (0 = Online)
    // (1 = Offline)
    if( _pcapRequestOnlineOffline() )
    {
      // Offline. Get the filename to be read.
      _pcapRequestFileToParse( &FileName );
    }
    else
    {
      // Online.
      int SelectedInterface;
      // Request an interface from user.(Get an index)
      SelectedInterface = _pcapRequestInterfaceFromUser();
      // Get a psNetStruct from the index.
      psNetStruct = _pcapGetInterfacePerIndex(SelectedInterface, psNetStruct );
      // Print Info about the selected interface.
      _pcapPrintInterfaceInfo( psNetStruct );
    }
};

void PCAPLib::PCAPCaptureStart( pcap_handler pfCallbackFunction )
{
  pcap_t *psPcapDescriptor = NULL;

  if(psNetStruct != NULL )
  {
    // Live Parsing
    cout << "pcap_open_live()" << endl;
    psPcapDescriptor = pcap_open_live(psNetStruct->name, BUFSIZ,1,100, errbuf);
    if (psPcapDescriptor == NULL)
    {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return;
    }
  }
  else
  {
    // Parse a file
    cout << "pcap_open_offline()" << endl;
    psPcapDescriptor = pcap_open_offline( FileName.c_str(), errbuf);
    if (psPcapDescriptor == NULL)
    {
      cout << "pcap_open_offline() failed: " << errbuf << endl;
      return;
    }
  }

  if(psPcapDescriptor != NULL)
  {
    //_pcapReadInLoop( psPcapDescriptor );
    _pcapReadInCallback( psPcapDescriptor, pfCallbackFunction );
  }
  cout << errbuf << endl;
  return;
};
