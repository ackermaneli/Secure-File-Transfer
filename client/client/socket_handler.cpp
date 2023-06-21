/*
	TransferIt client
	socket_handler.cpp
	description: file which handle socket operations (connect, read, write, etc) 
*/

#include "socket_handler.h"

SocketHandler::SocketHandler()
{
	// set endianess 
	unsigned int i = 1;
	char* c = (char*)&i;
	if (*c)
		little_endian = true;
	else
		little_endian = false;

	is_connected = false;
	io_context = nullptr;
	socket = nullptr;
	resolver = nullptr;
}

SocketHandler::~SocketHandler()
{
	close_connection();
}

/*
changing the endianess type, 
this function do not handle platforms which byte is not 8bit
*/
void SocketHandler::endianess_swaping(uint8_t* buff, size_t size)
{
	if (buff == nullptr || size < sizeof(uint32_t))
		return;

	size -= (size % sizeof(uint32_t));
	uint32_t* const p_buff = reinterpret_cast<uint32_t* const>(buff);
	for (size_t i = 0; i < size; ++i)
	{
		uint32_t temp = ((buff[i] << 8) & 0xFF00FF00) | ((buff[i] >> 8) & 0xFF00FF);
		buff[i] = (temp << 16) | (temp >> 16);
	}
}

// connect to the socket, return false if not succeeded
bool SocketHandler::connect()
{
	if (!addr_validation(addr) || !port_validation(port))
		return false;
	
	try
	{
		close_connection();

		io_context = new boost::asio::io_context;
		socket = new tcp::socket(*io_context);
		resolver = new tcp::resolver(*io_context);
		boost::asio::connect(*socket, resolver->resolve(addr, port));
		
		is_connected = true;
	}
	catch(const std::exception& e)
	{
		is_connected = false;
		std::cout << e.what() << std::endl;
	}

	return is_connected; // ***************************
}

//
bool SocketHandler::write_to_socket(const uint8_t* buff, size_t size)
{
	if(buff == nullptr || socket == nullptr || is_connected == false || size == 0)
		return false;

	boost::system::error_code ec;

	uint8_t* temp_buff = new uint8_t[size];// on the heap
	memcpy(temp_buff, buff, size);

	if (!little_endian)
		endianess_swaping(temp_buff, size);
	
	size_t bytes_transferred = boost::asio::write(*socket, boost::asio::buffer(temp_buff, size), ec);

	delete[] temp_buff; // we shall de-allocate the memory

	if (!bytes_transferred) // nothing was written so we shall return false
		return false;
	if (ec) // write went non-successfully
		return false;

	return true;
}

//
bool SocketHandler::recv_from_socket(uint8_t* buff, size_t size)
{
	if (buff == nullptr || socket == nullptr || is_connected == false || size == 0)
		return false;

	boost::system::error_code ec;

	size_t bytes_transferred = boost::asio::read(*socket, boost::asio::buffer(buff, size), ec);

	if (!bytes_transferred || ec) // recieved nothing or some error accured
		return false;

	if (!little_endian)
		endianess_swaping(buff, bytes_transferred);

	return true;
}

void SocketHandler::close_connection()
{
	if (socket != nullptr)
		socket->close();

	is_connected = false;

	delete io_context;
	delete socket;
	delete resolver;
	resolver = nullptr;
	socket = nullptr;
	io_context = nullptr;
}

// validate an ip address (v4)
bool SocketHandler::addr_validation(const std::string& address)
{
	try
	{
		(void)boost::asio::ip::address_v4::from_string(address);
	}
	catch(std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return false;
	}

	return true;
}

// validate a port which coming in a string type
bool SocketHandler::port_validation(const std::string& prt)
{
	try
	{
		int temp_port = boost::lexical_cast<int>(prt);
		
		if (temp_port == 0 || temp_port > PORT_MAX)
			return false;

	}
	catch(const boost::bad_lexical_cast& b)
	{
		std::cout << b.what() << std::endl;
		return false;
	}
}

bool SocketHandler::set_socket(const std::string& address, const std::string& prt)
{
	if (addr_validation(address) == false || port_validation(prt) == false)
		return false;

	addr = address;
	port = prt;
	return true;
}
