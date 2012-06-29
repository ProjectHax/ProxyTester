#include "stdio.h"
#include <iostream>
#include <stdint.h>
#include <fstream>
#include <string>

#include "stream_utility.h"

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>

// http://en.wikipedia.org/wiki/SOCKS
bool TestProxy(const std::string & host, uint16_t port, const std::string & username = "", const std::string & password = "")
{
	//International Silkroad Online
	uint32_t remote_address = inet_addr("121.128.133.26");
	uint16_t remote_port = htons(15779);

	boost::system::error_code ec;
	boost::asio::io_service io_service;
	boost::asio::ip::tcp::socket socket(io_service);

	StreamUtility w, r;
	std::vector<uint8_t> buffer;
	buffer.resize(64);

	//Resolve the hostname
	boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), host, boost::lexical_cast<std::string>(port));
    boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query, ec);

	if(ec)
	{
		std::cout << "Could not resolve " << host << ":" << port << std::endl;
		return false;
	}

	//Connect to the socks server
	socket.connect(*iterator, ec);
	
	if(ec)
	{
		std::cout << "Could not connect to " << host << ":" << port << std::endl;
		return false;
	}

	w.Write<uint8_t>(4);					//SOCKS version (v4)
	w.Write<uint8_t>(1);					//TCP stream connection
	w.Write<uint16_t>(remote_port);			//TCP port
	w.Write<uint32_t>(remote_address);		//IP
	w.Write_Ascii("ProjectHax\0", 11);		//Username
	boost::asio::write(socket, boost::asio::buffer(w.GetStreamPtr(), w.GetStreamSize()), boost::asio::transfer_all(), ec);

	//Error sending data
	if(ec)
	{
		std::cout << "Unable to send data to " << host << ":" << port << std::endl;
		return false;
	}

	//Read the servers response
	socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);

	//Error receiving data
	if(ec)
	{
		std::cout << "Unable to receive data from " << host << ":" << port << std::endl;
		return false;
	}

	r = StreamUtility(&buffer[0], 63);
	r.Read<uint8_t>();						//Null byte
	uint8_t status = r.Read<uint8_t>();		//Status

	switch(status)
	{
		case 0x5a:	//Request granted
		{
			socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);
			r = StreamUtility(&buffer[0], 63);

			r.Read<uint16_t>();						//Size
			uint16_t opcode = r.Read<uint16_t>();	//Opcode

			socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			socket.close(ec);

			if(opcode == 0x5000)
				return true;
		}break;
		case 0x5b:	//Request rejected or failed
		{
		}break;
		case 0x5c:	//Request failed because client is not running identd
		{
			return false;
		}break;
		case 0x5d:	//Request failed because client's identd could not confirm the user ID string in the request
		{
			return false;
		}break;
	};

	socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	socket.close(ec);

	//Connect to the socks server
	socket.connect(*iterator, ec);
	
	if(ec)
	{
		std::cout << "Could not connect to " << host << ":" << port << std::endl;
		return false;
	}

	w.Clear();
	w.Write<uint8_t>(5);					//SOCKS version (v5)

	if(!username.empty())
	{
		w.Write<uint8_t>(2);					//Number of authentication methods supported (2)
		w.Write<uint8_t>(0);					//No authentication
		w.Write<uint8_t>(2);					//Username/password authentication
	}
	else
	{
		w.Write<uint8_t>(1);					//Number of authentication methods supported (1)
		w.Write<uint8_t>(0);					//No authentication
	}

	boost::asio::write(socket, boost::asio::buffer(w.GetStreamPtr(), w.GetStreamSize()), boost::asio::transfer_all(), ec);

	//Error sending data
	if(ec)
	{
		std::cout << "Unable to send data to " << host << ":" << port << std::endl;
		return false;
	}

	//Read the servers response
	socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);

	//Error receiving data
	if(ec)
	{
		std::cout << "Unable to receive data from " << host << ":" << port << std::endl;
		return false;
	}

	r = StreamUtility(&buffer[0], 63);
	uint8_t version = r.Read<uint8_t>();			//SOCKS version (must be v5)
	uint8_t authentication = r.Read<uint8_t>();		//Authentication method

	//No authentication
	if(version == 5)
	{
		w.Clear();

		//No authentication
		if(authentication == 0)
		{
			w.Write<uint8_t>(5);						//SOCKS version (v5)
			w.Write<uint8_t>(1);						//TCP stream connection
			w.Write<uint8_t>(0);						//Reserved
			w.Write<uint8_t>(1);						//Address type, (1 = IPv4 address, 3 = domain, 4 = IPv6 address)
			w.Write<uint32_t>(remote_address);			//IP
			w.Write<uint16_t>(remote_port);				//TCP port
		}
		//Username/password authentication
		else if(authentication == 2)
		{
			w.Write<uint8_t>(1);						//Authentication version
			w.Write<uint8_t>(username.length());		//Username length
			w.Write_Ascii(username);					//Username
			w.Write<uint8_t>(password.length());		//Password length
			w.Write_Ascii(password);					//Password
		}

		boost::asio::write(socket, boost::asio::buffer(w.GetStreamPtr(), w.GetStreamSize()), boost::asio::transfer_all(), ec);

		//Error sending data
		if(ec)
		{
			std::cout << "Unable to send data to " << host << ":" << port << std::endl;
			return false;
		}

		//Read the servers response
		socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);

		//Error receiving data
		if(ec)
		{
			std::cout << "Unable to receive data from " << host << ":" << port << std::endl;
			return false;
		}

		if(authentication == 2)
		{
			r = StreamUtility(&buffer[0], 63);
			if(r.Read<uint8_t>() != 1 || r.Read<uint8_t>() != 0)
				return false;

			w.Clear();
			w.Write<uint8_t>(5);						//SOCKS version (v5)
			w.Write<uint8_t>(1);						//TCP stream connection
			w.Write<uint8_t>(0);						//Reserved
			w.Write<uint8_t>(1);						//Address type, (1 = IPv4 address, 3 = domain, 4 = IPv6 address)
			w.Write<uint32_t>(remote_address);			//IP
			w.Write<uint16_t>(remote_port);				//TCP port

			boost::asio::write(socket, boost::asio::buffer(w.GetStreamPtr(), w.GetStreamSize()), boost::asio::transfer_all(), ec);

			//Error sending data
			if(ec)
			{
				std::cout << "Unable to send data to " << host << ":" << port << std::endl;
				return false;
			}

			//Read the servers response
			socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);

			//Error receiving data
			if(ec)
			{
				std::cout << "Unable to receive data from " << host << ":" << port << std::endl;
				return false;
			}
		}
		
		r = StreamUtility(&buffer[0], 10);
		version = r.Read<uint8_t>();				//SOCKS version (must be v5)
		status = r.Read<uint8_t>();			//Status

		switch(status)
		{
			case 0:	//Request granted
			{
				socket.read_some(boost::asio::buffer(&buffer[0], 63), ec);
				r = StreamUtility(&buffer[0], 63);

				r.Read<uint16_t>();						//Size
				uint16_t opcode = r.Read<uint16_t>();	//Opcode

				socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
				socket.close(ec);

				if(opcode == 0x5000)
					return true;
			}break;
			case 1:	//General failure
			{
			}break;
			case 2:	//Connection not allowed by ruleset
			{
			}break;
			case 3:	//Network unreachable
			{
			}break;
			case 4:	//Host unreachable
			{
			}break;
			case 5:	//Connection refused by destination host
			{
			}break;
			case 6:	//TTL expired
			{
			}break;
			case 7:	//Command not supported / protocol error
			{
			}break;
			case 8:	//Address type not supported
			{
			}break;
		};
	}

	socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	socket.close(ec);

	return false;
}

int main(int argc, char* argv[])
{
	std::ifstream ifs("proxy.txt");
	std::fstream fs("working.txt", std::ios::out);
	uint32_t working = 0;

	if(ifs.is_open() && fs.is_open())
	{
		std::string line;
		std::string host;
		uint16_t port;

		while(!ifs.eof())
		{
			ifs >> line;

			size_t index = line.find(":");
			if(index != std::string::npos)
			{
				host = line.substr(0, index);
				port = boost::lexical_cast<uint16_t>(line.substr(index + 1, line.length() - index));

				if(TestProxy(host, port))
				{
					fs << line << "\n";
					working++;
				}
			}
		}

		fs.close();
		ifs.close();
	}

	std::cout << "Done. " << working << " servers work." << std::endl;
	std::cin.get();
	return 0;
}