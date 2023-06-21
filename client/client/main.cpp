/* 
	TransferIt client
	main.cpp
	description: entry point for the client startup
*/

#include "client.h"
#include "iostream"

int main()
{
	Client clt;
	
	if (!clt.clt_start())
		clt.stop_clt();
	else
		std::cout << " Client routine went successfully! " << std::endl;

	return 0;	
}