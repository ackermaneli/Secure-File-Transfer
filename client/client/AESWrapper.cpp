/*
* TransferIt client
* AESWrapper.cpp
* file given by university
*/

#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step

void AESWrapper::GenerateKey(uint8_t* const buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key.symmetric_key, sizeof(_key.symmetric_key));
}

AESWrapper::AESWrapper(const CltSymmetricKey& symmetric_key)
{
	_key = symmetric_key;
}

AESWrapper::~AESWrapper()
{
	
}

std::string AESWrapper::encrypt(const uint8_t* plain, size_t length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key.symmetric_key, sizeof(_key.symmetric_key));
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(plain, length);
	stfEncryptor.MessageEnd();

	return cipher;
}

std::string AESWrapper::decrypt(const uint8_t* cipher, size_t length) 
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key.symmetric_key, sizeof(_key.symmetric_key));
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(cipher, length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
