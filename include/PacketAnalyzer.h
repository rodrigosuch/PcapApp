/*
 * PacketAnalyzer.h
 *
 *  Created on: 9 de set de 2018
 *      Author: rodrigo
 */

#ifndef PACKETANALYZER_H_
#define PACKETANALYZER_H_
#include <list>

class PacketAnalyzer
{
private:

public:

  PacketAnalyzer(void);
  pcap_handler PckAnlz_GetPacketReceivedCallback(void);

};

#endif /* PACKETANALYZER_H_ */
