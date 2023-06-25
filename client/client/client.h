/*
	TransferIt client
	client.h
	description: header file for client.cpp 
*/

#pragma once

#include <string>
#include "networkProtocol.h"

// both files should located with the exe file
const std::string CLT_INSTRUCTION_FILE = "transfer.info"; 
const std::string CLT_INFO_FILE = "me.info";

// file send retries
const int RETRIES = 4;

// forward declarations 
class FileHandler;
class SocketHandler;
class RSAPrivateWrapper;

class Client {

private:
	CltId id;
	std::string user_name;
	std::string file_to_send;
	CltPublicKey public_key;
	CltSymmetricKey symmetric_key;
	SocketHandler* socket_handler;
	FileHandler* file_handler;
	RSAPrivateWrapper* rsa_decryptor;
	uint32_t clt_cksum;
	uint32_t svr_cksum;

public:
	Client();
	virtual ~Client();

	// batch mode startup routine
	bool clt_start();

	// files
	bool read_instructions();
	bool read_clt_info();
	bool write_clt_info();

	// general
	bool check_response_hdr(const ResHeader& hdr, const uint16_t code);
	bool recv_changing_payload(const uint16_t code, uint8_t*& payload, size_t& payload_size);
	bool retries_mechanism();

	// request handlers
	bool req_registration();
	bool req_public_key();
	bool req_file();
	bool req_crc(const uint16_t type_code);
	
	// exit(1)
	void stop_clt();
};