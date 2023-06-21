/*
	TransferIt client
	socket_handler.h
	description: header file for socket_handler.cpp
*/

#pragma once

#include <boost/asio.hpp>
#include <string>
#include <cstdint>
#include <iostream>
#include <vector>
#include <boost/lexical_cast.hpp>

//MAYBE SEND IN CHUNKS
//const size_t PACKET = 9999;

const size_t PORT_MAX = 65535;

using boost::asio::ip::tcp;

class SocketHandler 
{
private:
	boost::asio::io_context* io_context;
	tcp::socket* socket;
	tcp::resolver* resolver;
	std::string addr;
	std::string port;
	bool little_endian; // will be used for endianess testing
	bool is_connected; // true if connected to the socket

public:
	SocketHandler();
	virtual ~SocketHandler();

	void endianess_swaping(uint8_t* buff, size_t size);
	
	bool connect();
	bool write_to_socket(const uint8_t* buff, size_t size);
	bool recv_from_socket(uint8_t* buff, size_t size);
	void close_connection();

	bool addr_validation(const std::string& address);
	bool port_validation(const std::string& prt);
	bool set_socket(const std::string& address, const std::string& prt);
};