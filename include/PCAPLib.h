/*
 * PCAPLib.h
 *
 *  Created on: 8 de set de 2018
 *      Author: rodrigo
 */

#ifndef PCAPLIB_H_
#define PCAPLIB_H_


class PCAPLib {
private:
  pcap_if_t * psNetStruct;
  char errbuf[PCAP_ERRBUF_SIZE];

public:
  PCAPLib( void );
  void PCAPInit( void );
  void PCAPStart( void );

/* what an App is */ };
#endif /* PCAPLIB_H_ */
