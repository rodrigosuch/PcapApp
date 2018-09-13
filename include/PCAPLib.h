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

public:
  PCAPLib( void );
  void PCAPInit( void );
  void PCAPCaptureStart( pcap_handler pfCallbackFunction );

/* what an App is */ };
#endif /* PCAPLIB_H_ */
