# Secure-File-Transfer
Defensive programming project that involves both server and client software for encrypted file transfer (part of OpenU course)  
  
## Server  
Python (3.8 or higher, written with 3.10)  
It depends on PyCryptoDome.  
_Use ```pip install -r server/requirements.txt``` to auto install_  

## Client  
C++ 17+, currently only run on x86 (Win32) only build config due to dependency management.  
Used Visual Studio 2022, dependencies explanation will be adjusted to it.  
It depends on:  
*[Boost](https://www.boost.org/) - asio  
*[CryptoPP](https://github.com/weidai11/cryptopp)  
*Hint - for Boost, use visual studio [vcpkg](https://vcpkg.io/en/getting-started.html) package manager*  
*Hint - for CryptoPP, create a folder named cryptopp inside your project folder (where the .SLN is located) clone or download the source from [cryptopp](https://github.com/weidai11/cryptopp/tree/34a34967ac560c1801bf3845dbac3ac63c1d4c05) inside the directory. From [Visual Studio->Solution Explorer] click on [Solution->Add->Existing Project] and select the cryptlib.vcproj file to include in your solution*
