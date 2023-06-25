/*
	TransferIt client
	helper.cpp
	description: file which contains helper / utils functions
*/

#include "helper.h"
#include "crc.h"
#include <base64.h>
#include <boost/crc.hpp>
std::string Helper::base64_encode(const std::string& s)
{
	std::string encoded;
	CryptoPP::StringSource ss(s, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded))); 
	return encoded;
}

std::string Helper::base64_decode(const std::string& s)
{
	std::string decoded;
	CryptoPP::StringSource ss(s, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded))); 
	return decoded;
}

uint32_t Helper::get_crc32(uint8_t* buff, size_t num_of_bytes)
{
	try 
	{
		CRC digest = CRC();
		digest.update(reinterpret_cast<unsigned char*>(buff), num_of_bytes);
		uint32_t cksum = digest.digest();
		return cksum;
	}
	catch(std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return 0;
	}
}