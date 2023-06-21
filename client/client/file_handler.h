/*
	TransferIt client
	file_handler.h
	description: header file for file_handler.cpp
*/

#pragma once

#include <fstream>
#include <string>
#include <cstdint>
#include <iostream>

class FileHandler 
{
private:
	std::fstream* fs;
	std::string file_path; 


public:
	FileHandler();
	virtual ~FileHandler();

	void clear_handler();
	size_t get_file_size();
	bool open_file(const std::string& fn, const std::string& type);
	bool read_file_bytes(uint8_t* buff, size_t num_of_bytes);
	bool read_one_line(std::string& buff);
	bool write_file_bytes(const uint8_t* buff, size_t num_of_bytes);
	bool write_one_line(const std::string& buff);
	//*****************
	// bool open_and_read(uint8_t*& f, size_t& num_of_bytes, const std::string& fn);
	// bool open_and_write(const std::string& buff, const std::string fn);
	//*****************


};