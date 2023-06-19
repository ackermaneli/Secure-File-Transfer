# Secure-File-Transfer
Defensive programming project that involves both server and client software for encrypted file transfer (part of OpenU course)  
  
## Server  
  
Python (written with 3.10.8)  
  
It depends on PyCryptoDome.  
  
_Use ```pip install -r server/requirements.txt``` to auto install_   
  
## Client  
  
C++ 17+, currently only run on x86 (Win32) only build config due to dependency management.  
  
Used Visual Studio 2022, dependencies explanation will be adjusted to it.  
  
It depends on:  
- [Boost](https://www.boost.org/) - asio  
- [CryptoPP](https://github.com/weidai11/cryptopp)
  
*Hint - for Boost, use visual studio [vcpkg](https://vcpkg.io/en/getting-started.html) package manager*  
  
*Hint - for CryptoPP, create a folder named cryptopp inside your project folder (where the .SLN is located) clone or download the source from [cryptopp](https://github.com/weidai11/cryptopp/tree/34a34967ac560c1801bf3845dbac3ac63c1d4c05) inside the directory. From [Visual Studio->Solution Explorer] click on [Solution->Add->Existing Project] and select the cryptlib.vcproj file to include in your solution*  

## Usage  
To see how the software works, for example:  
- Modify the ```transfer.info``` file in the ```client``` directory with the name you want to store the files in (second line after the address) (this name will be the directory which the server will store the files the client send).  
- Create a file (```.txt``` / ```.docx``` for example) in the client directory and write this file name in the ```transfer.info``` file in line 3 (and next lines if there's more files to send).  
- Start the server program to listen for connections, meanwhile start the client program to connect with the server and complete the process.
