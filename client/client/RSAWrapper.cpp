/*
* TransferIt client
* RSAWrapper.cpp
* file given by university
*/

#include "networkProtocol.h"
#include "RSAWrapper.h"

RSAPublicWrapper::RSAPublicWrapper(const CltPublicKey& public_key)
{
	CryptoPP::StringSource ss((public_key.public_key), sizeof(public_key.public_key), true);
	_publicKey.Load(ss);
}

RSAPublicWrapper::~RSAPublicWrapper()
{

}

std::string RSAPublicWrapper::encrypt(const uint8_t* plain, size_t length)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(plain, length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}



RSAPrivateWrapper::RSAPrivateWrapper()
{
	_privateKey.Initialize(_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{

}

std::string RSAPrivateWrapper::getPrivateKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

std::string RSAPrivateWrapper::getPublicKey() const
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

// ****************************** decrypt ?????????
std::string RSAPrivateWrapper::decrypt(const uint8_t* cipher, size_t length)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}






