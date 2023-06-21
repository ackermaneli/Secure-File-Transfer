/*
	TransferIt client
	file_handler.cpp
	description: handle file operations
*/

#include "file_handler.h"
#include <boost/filesystem.hpp>

FileHandler::FileHandler()
{
	fs = nullptr;
	file_path = "";
}

FileHandler::~FileHandler()
{
	clear_handler();
}

// close a file and clear file name
void FileHandler::clear_handler()
{
	if (fs != nullptr)
		fs->close();

	delete fs;
	fs = nullptr;
	file_path = "";
}

// get the size (in bytes) of this file, return 0 on failure
size_t FileHandler::get_file_size()
{
	if (fs == nullptr || !fs->is_open())
		return 0;

	uintmax_t fsize = boost::filesystem::file_size(file_path);
	
	if (fsize > UINT32_MAX) // up to 4gb files 
		return 0;

	return static_cast<size_t>(fsize);
}

/* attempt to open a file given a file name
(only support binary reading / writing, only support file names not full path) */
bool FileHandler::open_file(const std::string& fn, const std::string& type)
{
	auto mode = (std::fstream::binary | std::fstream::in); // default is read binary

	if(type == "wb")
		mode = (std::fstream::binary | std::fstream::out);
	else if(type != "rb") // if its now wb or rb we don't support it
		return false;

	if (fn.size() == 0)
		return false;

	bool result = false;

	try 
	{
		fs = new std::fstream;
		fs->open(fn, mode);
		result = fs->is_open();
		if (result)
			file_path = fn;
	}
	catch(std::exception& e)
	{
		return false;
	}

	return result;
}

// read num_of_bytes from this filestream into buff
bool FileHandler::read_file_bytes(uint8_t* buff, size_t num_of_bytes)
{
	if (num_of_bytes == 0 || file_path.size() == 0 || fs == nullptr || buff == nullptr)
		return false;

	try
	{
		fs->read(reinterpret_cast<char*>(buff), num_of_bytes);
		return true;
	}
	catch(std::exception& e)
	{
		return false;
	}
}

// read one line from this file stream into buff
bool FileHandler::read_one_line(std::string& buff)
{
	if (fs == nullptr)
		return false;

	bool result = false;

	try
	{
		if (std::getline(*fs, buff) && buff.size() != 0)
			result = true;
	}
	catch(std::exception& e)
	{
		return false;
	}

	return result;
}


// write num_of_bytes from buff to this filestream 
bool FileHandler::write_file_bytes(const uint8_t* buff, size_t num_of_bytes)
{
	if (num_of_bytes == 0 || file_path.size() == 0 || fs == nullptr || buff == nullptr)
		return false;

	try
	{
		fs->write(reinterpret_cast<const char*>(buff), num_of_bytes);
		return true;
	}
	catch (std::exception& e)
	{
		return false;
	}
}

// write one line 
bool FileHandler::write_one_line(const std::string& buff)
{
	std::string temp_buff = buff;
	temp_buff.append("\n");
	return write_file_bytes(reinterpret_cast<const uint8_t*>(temp_buff.c_str()), temp_buff.size());
}

