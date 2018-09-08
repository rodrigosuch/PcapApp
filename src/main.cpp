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

using namespace std;

int main()
{
  PCAPLib PCAPInterface;

  PCAPInterface.PCAPInit();

  PCAPInterface.PCAPCaptureStart();
}
