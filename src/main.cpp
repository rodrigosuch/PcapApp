//============================================================================
// Name        : TCPAnalyse.cpp
// Author      : Rodrigo Such
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <pcap.h>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#include "PCAPLib.h"
#include "PacketAnalyzer.h"

using namespace std;

int main()
{
  PCAPLib PCAPInterface;
  PacketAnalyzer PacketAnalyzer;

  PCAPInterface.PCAPInit();

  PCAPInterface.PCAPCaptureStart(PacketAnalyzer.PckAnlz_GetPacketReceivedCallback());
}
