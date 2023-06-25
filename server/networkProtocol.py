"""
TransferIt server
networkProtocol.py
description: a file which contains all the network protocol details such as constants and requests&responses structs
"""

import struct

# initialization value
DEFAULT = 0

# Request codes
REQ_REGISTRATION = 1100  # SERVER SHOULD IGNORE UUID
REQ_PUBLIC_KEY = 1101
REQ_FILE = 1103
REQ_VALID_CRC = 1104
REQ_NVALID_CRC = 1105
REQ_4NVALID_CRC = 1106

# Response codes
RES_REGISTRATION_SUCCESS = 2100
RES_REGISTRATION_FAIL = 2101  # no payload
RES_AES_KEY = 2102  # variable payload size
RES_GOT_FILE = 2103
RES_MSG_CONFIRM = 2104  # no payload

# Server version
SVR_VERSION = 3

# sizes in bytes
CLT_ID_SIZE = 16
CLT_USERNAME_SIZE = 255
CLT_PUBLICKEY_SIZE = 160
CLT_SYMMETRICKEY_SIZE = 16
FILE_NAME_SIZE = 255
FILE_PATH_NAME_SIZE = 255
CKSUM_SIZE = 4
HEADER_SIZE = 7  # Version, Code, Payload size


# Request header
class ReqHeader:
    def __init__(self):
        self.clt_id = b""
        self.clt_version = DEFAULT
        self.req_code = DEFAULT
        self.payload_size = DEFAULT
        self.size = CLT_ID_SIZE + HEADER_SIZE

    def unpack(self, byte_array):
        """ unpack request header in little endian (<) """
        try:
            self.clt_id = struct.unpack(f"<{CLT_ID_SIZE}s", byte_array[:CLT_ID_SIZE])[0]
            # getting the header without the id by skipping the id
            self.clt_version, self.req_code, self.payload_size = \
                struct.unpack("<BHL", byte_array[CLT_ID_SIZE:CLT_ID_SIZE + HEADER_SIZE])
            return True
        except Exception as e:
            self.__init__()
            return False


# Request's

class ReqRegistration:
    def __init__(self):
        self.header = ReqHeader()
        self.clt_name = b""

    def unpack(self, byte_array):
        """ unpack request registration in little endian (<) """
        if not self.header.unpack(byte_array):
            return False
        try:
            # getting the name without the header, partitioning the null termination
            name_bytes = byte_array[self.header.size:self.header.size + CLT_USERNAME_SIZE]
            self.clt_name = str(
                struct.unpack(f"<{CLT_USERNAME_SIZE}s", name_bytes)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except Exception as e:
            self.clt_name = b""
            return False


class ReqPublicKey:
    def __init__(self):
        self.header = ReqHeader()
        self.clt_name = b""
        self.clt_public_key = b""

    def unpack(self, byte_array):
        """ unpack request public key in little endian (<) """
        if not self.header.unpack(byte_array):
            return False
        try:
            name_bytes = byte_array[self.header.size:self.header.size + CLT_USERNAME_SIZE]
            self.clt_name = str(
                struct.unpack(f"<{CLT_USERNAME_SIZE}s", name_bytes)[0].partition(b'\0')[0].decode('utf-8'))
            key_bytes = byte_array[
                        self.header.size + CLT_USERNAME_SIZE:self.header.size + CLT_USERNAME_SIZE + CLT_PUBLICKEY_SIZE]
            self.clt_public_key = struct.unpack(f"<{CLT_PUBLICKEY_SIZE}s", key_bytes)[0]
            return True
        except Exception as e:
            self.clt_name = b""
            self.clt_public_key = b""
            return False


class ReqFile:
    def __init__(self):
        self.header = ReqHeader()
        self.clt_id = b""
        self.content_size = DEFAULT
        self.file_name = b""
        self.content = b""

    def unpack(self, client_socket, data):
        """ unpack request file in little endian (<) """
        if not self.header.unpack(data):
            return False
        try:
            data = client_socket.recv(self.header.payload_size)  # getting the payload
            id_bytes = data[:CLT_ID_SIZE]
            self.clt_id = struct.unpack(f"<{CLT_ID_SIZE}s", id_bytes)[0]
            self.content_size = struct.unpack("<L", data[CLT_ID_SIZE:CLT_ID_SIZE + 4])[0]
            filename_bytes = data[CLT_ID_SIZE + 4: CLT_ID_SIZE + 4 + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{FILE_NAME_SIZE}s", filename_bytes)[0].partition(b'\0')[0].decode())  # .decode('utf-8')
            content_bytes = data[CLT_ID_SIZE + 4 + FILE_NAME_SIZE:]
            self.content = struct.unpack(f"<{self.content_size}s", content_bytes)[0]
            return True
        except Exception as e:
            self.clt_id = b""
            self.content_size = DEFAULT
            self.file_name = b""
            self.content = b""
            return False


class ReqCRC:
    def __init__(self):
        self.header = ReqHeader()
        # already got ID from header but keep with the protocol nature
        # (protocol should be changed but university decided to keep with this version)
        self.clt_id = b""
        self.file_name = b""

    def unpack(self, byte_array):
        """ unpack request CRC type (valid/ not valid/ 4th time not valid) in little endian (<) """
        if not self.header.unpack(byte_array):
            return False
        try:
            id_bytes = byte_array[self.header.size:self.header.size + CLT_ID_SIZE]
            self.clt_id = struct.unpack(f"<{CLT_ID_SIZE}s", id_bytes)[0]
            file_name_bytes = byte_array[self.header.size + CLT_ID_SIZE:self.header.size + CLT_ID_SIZE + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{FILE_NAME_SIZE}s", file_name_bytes)[0].partition(b'\0')[0].decode())
            return True
        except Exception as e:
            self.clt_id = b""
            self.file_name = b""
            return False


# Response header
class ResHeader:
    def __init__(self, res_code):
        self.svr_version = SVR_VERSION
        self.res_code = res_code
        self.payload_size = DEFAULT
        self.size = HEADER_SIZE

    def pack(self):
        """ pack response header in little endian (<) """
        try:
            return struct.pack("<BHL", self.svr_version, self.res_code, self.payload_size)
        except Exception as e:
            return b""


# Response's

class ResRegistration:
    def __init__(self):
        self.header = ResHeader(RES_REGISTRATION_SUCCESS)  # check about RES_REGISTRATION_FAILED both here and on client
        self.clt_id = b""

    def pack(self):
        """ pack response success registration in little endian (<) """
        try:
            byte_stream = self.header.pack()
            byte_stream += struct.pack(f"<{CLT_ID_SIZE}s", self.clt_id)
            return byte_stream
        except Exception as e:
            return b""


class ResAES:
    def __init__(self):
        self.clt_id = b""
        self.encrypted_aes_key = b""

    def pack(self):
        """ pack response got public key and sending encrypted AES key """
        try:
            byte_stream = struct.pack(f"<{CLT_ID_SIZE}s", self.clt_id)
            byte_stream += struct.pack(f"<{len(self.encrypted_aes_key)}s", self.encrypted_aes_key)
            return byte_stream
        except Exception as e:
            return b""


class ResGotFile:
    def __init__(self):
        self.header = ResHeader(RES_GOT_FILE)
        self.clt_id = b""
        self.content_size = 0
        self.file_name = b""
        self.cksum = 0

    def pack(self):
        """ pack response got file in little endian (<) """
        try:
            byte_stream = self.header.pack()
            byte_stream += struct.pack(f"<{CLT_ID_SIZE}s", self.clt_id)
            byte_stream += struct.pack("<L", self.content_size)
            byte_stream += struct.pack(f"<{FILE_NAME_SIZE}s", bytes(self.file_name, 'utf-8'))
            byte_stream += struct.pack("<L", self.cksum)
            return byte_stream
        except Exception as e:
            return b""


class ResConfirmMsg:
    def __init__(self):
        self.header = ResHeader(RES_MSG_CONFIRM)

    def pack(self):
        """ pack response msg confirm in little endian (<) """
        try:
            byte_stream = self.header.pack()
            return byte_stream
        except Exception as e:
            return b""


class ResRegistrationFailed:
    def __init__(self):
        self.header = ResHeader(RES_REGISTRATION_FAIL)

    def pack(self):
        """ pack response registration failed in little endian (<) """
        try:
            byte_stream = self.header.pack()
            return byte_stream
        except Exception as e:
            return b""
