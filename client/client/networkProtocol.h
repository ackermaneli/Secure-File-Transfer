/*
	TransferIt client
	networkProtocol.h
	description: a file which contains all the network protocol details such as constants and structs
*/

#pragma once

#include <cstdint>  // for uintX_t types

// initialization value
const int DEFAULT = 0;

// Request codes
const uint16_t REQ_REGISTRATION = 1100; // SERVER SHOULD IGNORE UUID
const uint16_t REQ_PUBLIC_KEY = 1101;
const uint16_t REQ_FILE = 1103;
const uint16_t REQ_VALID_CRC = 1104;
const uint16_t REQ_NVALID_CRC = 1105;
const uint16_t REQ_4NVALID_CRC = 1106;


// Response codes
const uint16_t RES_REGISTRATION_SUCCESS = 2100;
const uint16_t RES_REGISTRATION_FAIL = 2101;
const uint16_t RES_AES_KEY = 2102;
const uint16_t RES_GOT_FILE = 2103;
const uint16_t RES_MSG_CONFIRM = 2104;

// Client version
const uint8_t CLT_VERSION = 3;

// Request & Response fields sizes (bytes)
const size_t CLT_ID_SIZE = 16;
const size_t CLT_USERNAME_SIZE = 255; // including null terminated
const size_t CLT_PUBLICKEY_SIZE = 160; 
const size_t CLT_SYMMETRICKEY_SIZE = 16;
const size_t FILE_NAME_SIZE = 255;

#pragma pack(push, 1)

struct CltId 
{
	uint8_t uuid[CLT_ID_SIZE];
	CltId() : uuid{ DEFAULT } {}
};

struct CltName 
{
	uint8_t username[CLT_USERNAME_SIZE];
	CltName() : username{ '\0' } {}
};

struct CltPublicKey
{
	uint8_t public_key[CLT_PUBLICKEY_SIZE];
	CltPublicKey() : public_key{ DEFAULT } {}
};

struct CltSymmetricKey
{
	uint8_t symmetric_key[CLT_SYMMETRICKEY_SIZE];
	CltSymmetricKey() : symmetric_key{ DEFAULT } {}
};

struct FileName 
{
	uint8_t file_name[FILE_NAME_SIZE];
	FileName() : file_name{ DEFAULT } {}
};

struct FileCksum
{
	
};

// protocol Request header 

struct ReqHeader 
{
	CltId clt_id;
	uint8_t clt_version;
	uint16_t req_code;
	uint32_t payload_size;

	// constructor without client ID for registration type request
	ReqHeader(const uint16_t request_code) : clt_version(CLT_VERSION), req_code(request_code), payload_size(DEFAULT) {}

	// constructor with client id
	ReqHeader(const CltId& id, const uint16_t request_code) : clt_id(id), clt_version(CLT_VERSION), req_code(request_code), payload_size(DEFAULT) {}
};

// Request payload types

struct ReqRegistration
{
	ReqHeader hdr;
	CltName payload;

	ReqRegistration() : hdr(REQ_REGISTRATION) {}
};

struct ReqPublicKey
{
	ReqHeader hdr;
	struct
	{
		CltName clt_name;
		CltPublicKey clt_public_key;
	}payload;

	ReqPublicKey(const CltId& id) : hdr(id, REQ_PUBLIC_KEY) {}
};

struct ReqFile
{
	ReqHeader hdr;
	struct PayloadHdr
	{
		CltId clt_id;
		uint32_t file_content_size;
		FileName file_name;
		PayloadHdr(const CltId& id) : clt_id(id), file_content_size(DEFAULT) {}
	}payload_hdr;

	ReqFile(const CltId& id) : hdr(id, REQ_FILE), payload_hdr(id) {}
};

struct ReqValidCRC
{
	ReqHeader hdr;
	struct Payload
	{
		CltId clt_id;
		FileName file_name;
		Payload(const CltId& id) : clt_id(id) {}
	}payload;

	ReqValidCRC(const CltId& id) : hdr(id, REQ_VALID_CRC), payload(id) {}
};

struct ReqNValidCRC
{
	ReqHeader hdr;
	struct Payload
	{
		CltId clt_id;
		FileName file_name;
		Payload(const CltId& id) : clt_id(id) {}
	}payload;

	ReqNValidCRC(const CltId& id) : hdr(id, REQ_NVALID_CRC), payload(id) {}
};

struct Req4NValidCRC
{
	ReqHeader hdr;
	struct Payload
	{
		CltId clt_id;
		FileName file_name;
		Payload(const CltId& id) : clt_id(id) {}
	}payload;

	Req4NValidCRC(const CltId& id) : hdr(id, REQ_4NVALID_CRC), payload(id) {}
};

// Response header
struct ResHeader
{
	uint8_t svr_version;
	uint16_t res_code;
	uint32_t payload_size;
	ResHeader() : svr_version(DEFAULT), res_code(DEFAULT), payload_size(DEFAULT) {}
};

// Response payload types

struct ResRegistration
{
	ResHeader hdr;
	CltId payload;
};

struct ResAES
{
	CltId clt_id;
	/* variable Size content  */
};

struct ResGotFile
{
	ResHeader hdr;
	struct Payload
	{
		CltId clt_id;
		uint32_t file_content_size;
		FileName file_name;
		uint32_t cksum;
	}payload;
};

struct ResConfirmMsg
{
	ResHeader hdr;
};

#pragma pack(pop)


