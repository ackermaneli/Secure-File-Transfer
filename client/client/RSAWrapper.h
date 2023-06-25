/*
* TransferIt client
* RSAWrapper.h
* file given by university
*/

#pragma once

#include "networkProtocol.h"
#include <osrng.h>
#include <rsa.h>
#include <string>

class RSAPublicWrapper
{
public:
	static const size_t KEYSIZE = CLT_PUBLICKEY_SIZE;
	static const size_t BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PublicKey _publicKey;

public:
	RSAPublicWrapper(const CltPublicKey& public_key);
	virtual ~RSAPublicWrapper();

	std::string encrypt(const uint8_t* plain, size_t length);
};

class RSAPrivateWrapper
{
public:
	static const size_t BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey      _privateKey;

public:
	RSAPrivateWrapper();
	RSAPrivateWrapper(const std::string& key);
	virtual ~RSAPrivateWrapper();

	std::string getPrivateKey() const;
	std::string getPublicKey() const;
	std::string decrypt(const uint8_t* cipher, size_t length);
};

