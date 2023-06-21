/*
* TransferIt client
* AESWrapper.h
* file given by university
*/

#pragma once

#include "networkProtocol.h"
#include <string>

class AESWrapper
{
private:
	CltSymmetricKey _key;

public:
	static void GenerateKey(uint8_t* buffer, unsigned int length);

	AESWrapper();
	AESWrapper(const CltSymmetricKey& symmetric_key);
	virtual ~AESWrapper();

	CltSymmetricKey getKey() const;

	std::string encrypt(const uint8_t* plain, size_t length);
	std::string decrypt(const uint8_t* cipher, size_t length);
	std::string encrypt(const std::string& plain);
};

