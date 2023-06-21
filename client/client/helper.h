/*
	TransferIt client
	helper.h
	description: header file for helper.cpp
*/

#pragma once
#include <string>

namespace Helper
{
	//both given by university
	std::string base64_encode(const std::string& s);
	std::string base64_decode(const std::string& s);
	uint32_t get_crc32(uint8_t* buff, size_t num_of_bytes);
};


