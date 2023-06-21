/*
	TransferIt client
	client.cpp
	description: the main file of the client, contains the main client startup and requests handlers
*/

#include "client.h"
#include "socket_handler.h"
#include "file_handler.h"
#include "helper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <filesystem>

Client::Client()
{
	socket_handler = nullptr;
	socket_handler = new SocketHandler();

	file_handler = nullptr;
	file_handler = new FileHandler();

	rsa_decryptor = nullptr;
}

Client::~Client()
{
	delete socket_handler;
	delete file_handler;
	delete rsa_decryptor;
}

// stop the client from running, mainly created for an error in the client start up (clt_start)
void Client::stop_clt()
{
	socket_handler->close_connection();
	delete socket_handler;
	delete file_handler;
	delete rsa_decryptor;
	std::cout << " fatal-error XXXXX Server responded with an error, client routine went unsuccessfully XXXXXX fatal-error " << std::endl;
	exit(1);
}

// the main client routine, working in *batch mode*
bool Client::clt_start() 
{
	// read server ip address & port and set socket info, client username, and the file to send name
	if(!read_instructions())
	{
		std::cout << "couldn't read " << CLT_INSTRUCTION_FILE << std::endl;
		return false;
	}

	// connect to the server
	if(!socket_handler->connect())
	{
		std::cout << "couldn't connect to server" << std::endl;
		return false;
	}

	// case1: CLT_INFO_FILE exists - read username & UUID and private key
	if(std::filesystem::exists(CLT_INFO_FILE))
	{
		if (!read_clt_info())
		{
			socket_handler->close_connection();
			std::cout << "couldn't read" << CLT_INFO_FILE << " altho exists " << std::endl;
			return false;
		}
		
	}

	/* case2: CLT_INFO_FILE not exists - sends registration request and obtain username & UUID,
			 generate RSA pair and store username & UUID & private key in CLT_INFO_FILE
	*/
	else
	{
		if(!req_registration())
		{
			socket_handler->close_connection();
			std::cout << "registration failed" << std::endl;
			return false;
		}
		// generate RSA pair
		try
		{
			if(rsa_decryptor != nullptr)
				delete rsa_decryptor;
			rsa_decryptor = new RSAPrivateWrapper();
		}
		catch(std::exception& e)
		{
			std::cout << e.what() << std::endl;
			socket_handler->close_connection();
			return false;
		}
		// write client information into CLT_INFO_FILE
		if(!write_clt_info())
		{
			socket_handler->close_connection();
			std::cout << "couldn't store the information into the client info file" << std::endl;
			return false;
		}
	}
	 
	// (1) send public key to the server (2) recieve encrypted AES key (3) decrypt AES key with private key
	if (!req_public_key())
	{
		socket_handler->close_connection();
		std::cout << "request public key failed" << std::endl;
		return false;
	}

	// Encrypt the file to send with the AES key, send encrypted file to server, check both clt and svr cksum, send up to 4 times before abort
	if (!req_file())
	{
		socket_handler->close_connection();
		std::cout << "request file failed" << std::endl;
		return false;
	}
	if(!retries_mechanism())
	{
		socket_handler->close_connection();
		std::cout << " file retry send process went unsuccessfully " << std::endl;
		return false;
	}
	
	// close connection 
	socket_handler->close_connection();
	return true;
}

// read the server address & port from CLT_INSTRUCTION_FILE and set the socket info
bool Client::read_instructions()
{
	if (!file_handler->open_file(CLT_INSTRUCTION_FILE, "rb"))
		return false;

	// read server information - address & port and set socket info
	std::string svr_info;
	if (!file_handler->read_one_line(svr_info))
		return false;
	boost::algorithm::trim(svr_info);
	const size_t position = svr_info.find(':');
	const std::string address = svr_info.substr(0, position);
	const std::string port = svr_info.substr(position + 1);
	if (!socket_handler->set_socket(address, port))
		return false;

	// read client username
	std::string username;
	if (!file_handler->read_one_line(username))
		return false;
	boost::algorithm::trim(username);
	if (username.size() >= CLT_USERNAME_SIZE) // if == not enough for null terminated
		return false;
	for(auto c : username) // validate username - only alphabetic / numbers / spaces allowed 
	{
		if (!std::isalnum(c) && !std::isspace(c))
			return false;
	}
	user_name = username;

	// read file name
	std::string file_name;
	if (!file_handler->read_one_line(file_name))
		return false;
	boost::algorithm::trim(file_name);
	if (file_name.size() >= FILE_NAME_SIZE)
		return false;
	file_to_send = file_name;

	file_handler->clear_handler();
	return true;
}

// read username & UUID and private key from CLT_INFO_FILE
bool Client::read_clt_info()
{
	if (!file_handler->open_file(CLT_INFO_FILE, "rb"))
		return false;

	// read client username
	std::string username;
	if (!file_handler->read_one_line(username))
		return false;
	boost::algorithm::trim(username);
	if (username.size() >= CLT_USERNAME_SIZE) // if == not enough for null terminated
		return false;
	user_name = username;

	// read client UUID
	std::string UUID;
	if (!file_handler->read_one_line(UUID))
		return false;
	UUID = boost::algorithm::unhex(UUID);
	const char* unhexed_uuid = UUID.c_str();
	if(strlen(unhexed_uuid) != sizeof(id.uuid))
	{
		memset(id.uuid, 0, sizeof(id.uuid));
		return false;
	}
	memcpy(id.uuid, unhexed_uuid, sizeof(id.uuid));

	// read private key
	std::string decoded_key;
	std::string temp;
	while(file_handler->read_one_line(temp))
		decoded_key.append(Helper::base64_decode(temp));
	if (decoded_key.size() == 0)
		return false;
	try
	{
		delete rsa_decryptor;
		rsa_decryptor = new RSAPrivateWrapper(decoded_key);
	}
	catch(std::exception& e)
	{
		return false;
	}

	file_handler->clear_handler();
	return true;
}

// write client username & UUID & private key into CLT_INFO_FILE
bool Client::write_clt_info()
{
	if (!file_handler->open_file(CLT_INFO_FILE, "wb"))
		return false;

	// write client username
	if (!file_handler->write_one_line(user_name))
		return false;

	// write client UUID
	std::string string_b(id.uuid, id.uuid + sizeof(id.uuid));
	std::string uuid_hex = "";
	try
	{
		uuid_hex = boost::algorithm::hex(string_b);
	}
	catch(std::exception& e)
	{
		return false;
	}
	if (!file_handler->write_one_line(uuid_hex))
		return false;

	// write private key in base 64
	std::string key_encoded = Helper::base64_encode(rsa_decryptor->getPrivateKey());
	if (!file_handler->write_file_bytes(reinterpret_cast<const uint8_t*>(key_encoded.c_str()), key_encoded.size()))
		return false;

	file_handler->clear_handler();
	return true;
}


// attempt to register the client on the server, send a registration request and recieve response (uuid&username)
bool Client::req_registration()
{
	ReqRegistration req;
	ResRegistration res;

	// prepare header&payload
	req.hdr.payload_size = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.username), CLT_USERNAME_SIZE, user_name.c_str()); // strcpy_s is much safer than strcpy
	
	// write data into the socket
	const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req);
	size_t data_size = sizeof(req);
	if (!socket_handler->write_to_socket(data_to_send, data_size))
	{
		std::cout << "failed to send registration request" << std::endl;
		return false;
	}

	// recieve response data
	if (!socket_handler->recv_from_socket(reinterpret_cast<uint8_t*>(&res), sizeof(res))) 
	{
		std::cout << "failed to recieve server registration response" << std::endl;
		return false;
	}

	// check response header while the only desirable code is RES_REGISTRATION_SUCCESS, **if code is RES_REGISTRATION_FAIL it will check and we need to abort**
	if (!check_response_hdr(res.hdr, RES_REGISTRATION_SUCCESS)) 
	{
		std::cout << "header validation went unsuccessfully" << std::endl;
		return false;
	}

	// get UUID
	id = res.payload;
	return true;
}

// attempt to send public key request, recieve the response which contains the encrypted AES Symmetric key (decrypt the key after recieving)
bool Client::req_public_key()
{
	ReqPublicKey req(id);
	//ResAEY res;

	const auto publickey = rsa_decryptor->getPublicKey();
	if (publickey.size() != CLT_PUBLICKEY_SIZE)
		return false;

	// prepare header&payload
	req.hdr.payload_size = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.clt_name.username), CLT_USERNAME_SIZE, user_name.c_str()); 
	memcpy(req.payload.clt_public_key.public_key, publickey.c_str(), sizeof(req.payload.clt_public_key.public_key));

	// write data into the socket
	const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req);
	size_t data_size = sizeof(req);
	if (!socket_handler->write_to_socket(data_to_send, data_size))
	{
		std::cout << "failed to send public key request" << std::endl;
		return false;
	}

	// recieve unknown payload (cuz encrypted AES key size changes), decrypt AES key with private key, check AES key size (== CLT_SYMMETRICKEY_SIZE )
	uint8_t* payload = nullptr;
	size_t payload_size = 0;
	if(!recv_changing_payload(RES_AES_KEY, payload, payload_size))  
	{
		std::cout << "failed to recieve AES key from the server" << std::endl;
		return false;
	}

	// skip the ID, no need it for anything
	uint8_t* ptr = payload;
	ptr += sizeof(ResAES); 
	payload_size -= sizeof(ResAES);

	// decrypt symmetric key
	std::string aes_key;
	try
	{
		aes_key = rsa_decryptor->decrypt(ptr, payload_size);
	}
	catch(std::exception& e)
	{
		std::cout << "failed to decrypt AES key" << std::endl;
		return false;
	}
	if(aes_key.size() != CLT_SYMMETRICKEY_SIZE)
	{
		std::cout << "AES key after decryption size not match the protocol, size recieved: " << aes_key.size() << std::endl;
		return false;
	}
	memcpy(symmetric_key.symmetric_key, aes_key.c_str(), aes_key.size());
	delete[] payload;  // $ CRASH PLACE $
	return true;
}

// attempt to send a file to the server, obtain server response (mainly interested in the server cksum)
bool Client::req_file()
{
	ReqFile req(id);
	ResGotFile res;
	uint8_t* file_content = nullptr;
	try
	{
		strcpy_s(reinterpret_cast<char*>(req.payload_hdr.file_name.file_name), FILE_NAME_SIZE, file_to_send.c_str());
	}
	catch(std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return false;
	}

	// get file content
	if(!file_handler->open_file(file_to_send, "rb"))
	{
		std::cout << "cannot open file: " << file_to_send << std::endl;
		return false;
	}
	size_t num_of_bytes = file_handler->get_file_size();
	if(num_of_bytes == 0)
	{
		std::cout << "file is empty: " << file_to_send << std::endl;
		return false;
	}
	file_content = new uint8_t[num_of_bytes];
	if(!file_handler->read_file_bytes(file_content, num_of_bytes))
	{
		std::cout << "cannot read file contents: " << file_to_send << std::endl;
		delete[] file_content;
		return false;
	}
	// calc file cksum
	clt_cksum = Helper::get_crc32(file_content, num_of_bytes);
	if(!clt_cksum)
	{
		std::cout << "CRC of file" << file_to_send << " couldn't be calculated " << std::endl;
		return false;
	}
	file_handler->clear_handler();

	// encrypt file with AES Symmetric key
	AESWrapper aes(symmetric_key); 
	const std::string encrypted_file = aes.encrypt(file_content, num_of_bytes);
	req.payload_hdr.file_content_size = encrypted_file.size();
	uint8_t* content_to_send = new uint8_t[req.payload_hdr.file_content_size];
	memcpy(content_to_send, encrypted_file.c_str(), req.payload_hdr.file_content_size);
	delete[] file_content;

	// prepare header&payload, header will be sent first so server can check the payload size
	// 
	// header
	req.hdr.payload_size = sizeof(req.payload_hdr) + req.payload_hdr.file_content_size;
	const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req.hdr);
	size_t data_size = sizeof(req.hdr);
	if (!socket_handler->write_to_socket(data_to_send, data_size))
	{
		std::cout << "failed to send file request (header sending phase): " << file_to_send << std::endl;
		return false;
	}
	// payload
	uint8_t* payload = new uint8_t[sizeof(req.payload_hdr) + req.payload_hdr.file_content_size];
	memcpy(payload, &req.payload_hdr, sizeof(req.payload_hdr));
	memcpy(payload + sizeof(req.payload_hdr), content_to_send, req.payload_hdr.file_content_size);
	delete[] content_to_send;
	size_t payload_size = sizeof(req.payload_hdr) + req.payload_hdr.file_content_size;
	if(!socket_handler->write_to_socket(payload, payload_size))
	{
		std::cout << "failed to send file request (payload sending phase): " << file_to_send << std::endl;
		return false;
	}

	// recieve response - Got file 2103, we mainly look for the cksum CRC
	if(!socket_handler->recv_from_socket(reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		std::cout << "failed to recieve server response: 2103 (CRC)  " << file_to_send << std::endl;
		return false;
	}
	
	if(!check_response_hdr(res.hdr, RES_GOT_FILE))
	{
		std::cout << " ResGotFile header validation went unsuccessfully: " << file_to_send << std::endl;
		return false;
	}

	// get server cksum 
	svr_cksum = res.payload.cksum;
	return true;
}

// handle all types of CRC requests (valid crc, not valid crc, 4th time not valid crc
bool Client::req_crc(const uint16_t type_code)
{
	ResConfirmMsg res;
	if(type_code == REQ_VALID_CRC)
	{
		ReqValidCRC req(id);
		strcpy_s(reinterpret_cast<char*>(req.payload.file_name.file_name), FILE_NAME_SIZE, file_to_send.c_str());
		const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req);
		size_t data_size = sizeof(req);
		if (!socket_handler->write_to_socket(data_to_send, data_size))
		{
			std::cout << "failed to send valid CRC request" << std::endl;
			return false;
		}
	}
	else if(type_code == REQ_NVALID_CRC)
	{
		ReqNValidCRC req(id);
		strcpy_s(reinterpret_cast<char*>(req.payload.file_name.file_name), FILE_NAME_SIZE, file_to_send.c_str());
		const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req);
		size_t data_size = sizeof(req);
		if (!socket_handler->write_to_socket(data_to_send, data_size))
		{
			std::cout << "failed to send valid CRC request" << std::endl;
			return false;
		}
	}
	else if(type_code == REQ_4NVALID_CRC)
	{
		Req4NValidCRC req(id);
		strcpy_s(reinterpret_cast<char*>(req.payload.file_name.file_name), FILE_NAME_SIZE, file_to_send.c_str());
		const uint8_t* data_to_send = reinterpret_cast<const uint8_t*>(&req);
		size_t data_size = sizeof(req);
		if (!socket_handler->write_to_socket(data_to_send, data_size))
		{
			std::cout << "failed to send valid CRC request" << std::endl;
			return false;
		}
	}
	else
	{
		return false;  // not dealing with any other type
	}

	// recieve response data, response is the same for all kind of CRC requests
	if (!socket_handler->recv_from_socket(reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		std::cout << "failed to recieve CRC type response (Msg confirm: " << RES_MSG_CONFIRM << ") " << std::endl;
		return false;
	}

	if(!check_response_hdr(res.hdr, RES_MSG_CONFIRM))
	{
		std::cout << "Msg confirm response header validation went unsuccessfully" << std::endl;
	}

	return true;
}

// check the provided header with the provided response code, validate it
bool Client::check_response_hdr(const ResHeader& hdr, const uint16_t code)
{
	if(hdr.res_code != code)
	{
		std::cout << "response code: " << hdr.res_code << " not match the expected code: " << code << std::endl;
		return false;
	}
	
	uint32_t payload_expected_size = DEFAULT;
	if (hdr.res_code == RES_REGISTRATION_SUCCESS)
		payload_expected_size = sizeof(ResRegistration) - sizeof(ResHeader);
	else if (hdr.res_code == RES_GOT_FILE)
		payload_expected_size = sizeof(ResGotFile) - sizeof(ResHeader);
	else
		return true; // payload size changes (variable) or ResConfirmMsg type (only header no payload)
	if(hdr.payload_size != payload_expected_size)
	{
		std::cout << "Response payload size was not match to the expected payload size, expected: " << payload_expected_size << " , got: " << hdr.payload_size << std::endl;
		return false;
	}

	return true;
}

// recieve payload which we don't know (at first) it's size
bool Client::recv_changing_payload(const uint16_t code, uint8_t*& payload, size_t& payload_size)
{
	ResHeader res;
	// recieve response header
	if (!socket_handler->recv_from_socket(reinterpret_cast<uint8_t*>(&res), sizeof(res)))
		return false;

	// check header validation
	if (!check_response_hdr(res, code))
		return false;
	
	// recieve payload
	payload_size = res.payload_size;
	payload = new uint8_t[payload_size];
	if(!socket_handler->recv_from_socket(reinterpret_cast<uint8_t*>(payload), payload_size))
	{
		delete[] payload;
		payload = nullptr;
		payload_size = 0;
		return false;
	}

	return true;
}

// perform the Retry mechanism until client cksum == server cksum or until retry reach the maximum retries value (RETRIES)
bool Client::retries_mechanism()
{
	int i = 1;
	bool same_cksum = (clt_cksum == svr_cksum);
	while (!same_cksum && i < RETRIES)
	{
		if (!req_crc(REQ_NVALID_CRC))
		{
			std::cout << "failed to handle request unvalid crc (request code: " << REQ_NVALID_CRC << std::endl;
			return false;
		}
		if (!req_file())
		{
			std::cout << "request file failed" << std::endl;
			return false;
		}
		same_cksum = (clt_cksum == svr_cksum);
		i += 1;
	}
	if (!same_cksum)
	{
		if (!req_crc(REQ_4NVALID_CRC))
		{
			std::cout << "failed to handle request 4th time unvalid crc (request code: " << REQ_4NVALID_CRC << std::endl;
			return false;
		}
	}
	else // same_cksum == true
	{
		if (!req_crc(REQ_VALID_CRC))
		{
			std::cout << "failed to handle request valid crc (request code: " << REQ_VALID_CRC << std::endl;
			return false;
		}
	}

	return true;
}