"""
TransferIt server
server.py
description: main loop of the server and socket operations, contains server startup routine
"""

import networkProtocol
import database
import helper
import socket  # for socket operations (send recv)
import uuid  # for client id
import datetime  # for database LastSeen
import threading  # for multithreading sessions


class Server:
    """ class which represents the server, contains the main server startup routine """
    DATABASE = "server.db"
    DEFAULT_RECV_SIZE = 512

    def __init__(self, svr_addr, port):
        self.addr = svr_addr
        self.port = port
        self.database = database.Database(Server.DATABASE)
        self.req_handler = {
            networkProtocol.REQ_REGISTRATION: self.req_registration,
            networkProtocol.REQ_PUBLIC_KEY: self.req_public_key,
            networkProtocol.REQ_FILE: self.req_file}

    def svr_startup(self):
        """ """
        self.database.tables_init()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as svr_socket:
            try:
                svr_socket.bind((self.addr, self.port))
                svr_socket.listen()
            except Exception as e:
                print(e)
                return False

            print(f" Server socket binded to port {self.port} \n Server is listening for new connections ")
            while True:
                try:
                    # establish connection with client
                    clt_socket, addr = svr_socket.accept()
                    print(f"Connected by {addr}")

                    # create separate thread for client session
                    # self.session(clt_socket, addr)
                    clt_session_thread = threading.Thread(target=self.session, args=(clt_socket, addr))
                    clt_session_thread.start()
                except Exception as e:
                    print(f" server main loop raised an exception, details: {e}")
                    return False

    def session(self, clt_socket, clt_addr):
        """ starts a season with the client, each loop iteration
        is handling a request from the client, if a request couldn't be handle, the whole session will be over """
        with clt_socket:  # will close clt_socket when finish
            while True:
                # receive the first chunk of data from the client,
                # get the request code, and call the appropriate request handler
                data = clt_socket.recv(Server.DEFAULT_RECV_SIZE)
                if not data:
                    print(f" X failed to receive first chunk of request data, client {clt_addr} session will end now")
                    return

                # parse the request header and obtain the request code
                req_header = networkProtocol.ReqHeader()
                if not req_header.unpack(data):
                    print(f" X failed to unpack request header, client {clt_addr} session will end now")
                    return

                crc_type_codes = [networkProtocol.REQ_VALID_CRC, networkProtocol.REQ_NVALID_CRC,
                                  networkProtocol.REQ_4NVALID_CRC]
                # check whether the request code is a valid one
                if req_header.req_code in self.req_handler.keys():
                    # invoke the appropriate request handler based on the request code (not CRC type request)
                    if not self.req_handler[req_header.req_code](data, clt_socket):
                        print(
                            f" X couldn't handle request {req_header.req_code}, client {clt_addr} session will end now")
                        return

                # CRC type request
                elif req_header.req_code in crc_type_codes:
                    if not self.req_crc(data, clt_socket):
                        print(
                            f" X couldn't handle request {req_header.req_code}, client {clt_addr} session will end now")
                        return
                else:
                    print(
                        f" X request code {req_header.req_code} do not match any protocol request code,"
                        f" client {clt_addr} session will end now")
                    return

                self.database.set_last_seen(req_header.clt_id, str(datetime.datetime.now()))

    def req_registration(self, data, clt_socket):
        """ handles registration request """
        req = networkProtocol.ReqRegistration()
        res = networkProtocol.ResRegistration()
        # unpack request data and validation
        if not req.unpack(data):
            print(f"failed to unpack registration request data")
            return False
        try:
            valid = all(c.isalnum or c.isspace() for c in req.clt_name)
            if not valid:
                print(f"client username {req.clt_name} is invalid *registration request*")
                return False
            if self.database.clt_username_exists(req.clt_name):
                print(f"client username {req.clt_name} already exists *registration request*")
                return False
        except Exception as e:
            print(f"failed to connect to the database *registration request*")
            return False

        # create a client entry and store in database, public key and aes key are not known in this phase
        clt_entry = database.Client(uuid.uuid4().hex, req.clt_name, None, str(datetime.datetime.now()), None)
        if not self.database.store_clt(clt_entry):
            print(f"Failed to store client {req.clt_name} data in the database *registration request*")
            return False
        print(
            f"client {req.clt_name} is successfully registered, public key and aes key are None *registration request*")

        # attempt to send the appropriate response
        res.clt_id = clt_entry.ID
        res.header.payload_size = networkProtocol.CLT_ID_SIZE
        try:  # {maybe check if need to validate all was sent}
            clt_socket.send(res.pack())
        except Exception as e:
            print(f"failed to send response to {clt_socket} *registration request*")
            return False
        print(f"successfully sent response *registration request*")
        return True

    def req_public_key(self, data, clt_socket):
        """ handles public key request """
        req = networkProtocol.ReqPublicKey()
        res = networkProtocol.ResAES()
        res_hdr = networkProtocol.ResHeader(networkProtocol.RES_AES_KEY)
        if not req.unpack(data):
            print(f"failed to unpack public key data")
            return False
        try:
            if not self.database.clt_username_exists(req.clt_name):
                print(f"client {req.clt_name} not registered *publicKey request* ")
                return False
        except Exception as e:
            print("failed to connect to the database *publicKey request*")
            return False

        # update public key in database
        if not self.database.set_public_key(req.header.clt_id, req.clt_public_key):
            print(f"client {req.clt_name} public key cannot be stored in the database *publicKey request*")
            return False
        print(f"successfully stored public key of {req.clt_name} *publicKey request*")

        # create AES key and encrypt it with the client public key
        aes_key, encrypted_aes = helper.gen_aes(req.clt_public_key)
        if aes_key is None:
            return False
        # store aes key in database
        if not self.database.set_aes_key(req.header.clt_id, aes_key):
            print(
                f"AES key generated for client {req.clt_name} cannot be stored in the database *publicKey request*")
            return False

        # attempt to send the appropriate response, sending the header first
        res.clt_id = req.header.clt_id
        res.encrypted_aes_key = encrypted_aes
        res_hdr.payload_size = networkProtocol.CLT_ID_SIZE + len(encrypted_aes)
        try:  # {maybe check if need to validate all was sent}
            clt_socket.send(res_hdr.pack())  # send header
            clt_socket.send(res.pack())  # send payload
        except Exception as e:
            print(
                f"failed to send response HEADER to {clt_socket} *publicKey request*")  # ???????????????????????????????????????????
            return False
        print(f"successfully sent response *publicKey request*")
        return True

    def req_file(self, data, clt_socket):
        """ handles file request """
        req = networkProtocol.ReqFile()
        res = networkProtocol.ResGotFile()
        if not req.unpack(clt_socket, data):
            print(f"failed to unpack File data")
            return False
        try:
            if not self.database.clt_id_exists(req.clt_id):
                print(f"client ID {req.clt_id} not exists ")
                return False
        except Exception as e:
            print(f"failed to connect to the database")
            return False

        # decrypt file contents with the client AES key
        aes_key = self.database.get_clt_aes_key(req.clt_id)
        if not aes_key:
            print(f" AES Key of client with ID {req.clt_id} couldn't be retrieved from database")
            return False
        decrypted_file_content = helper.decrypt_content(aes_key, req.content)
        if decrypted_file_content is None:
            print(f"file {req.file_name} content couldn't be decrypted")
            return False

        # calculate file cksum (Identical to linux cksum command)
        cksum = helper.calc_crc(decrypted_file_content)
        if cksum is None:
            print(f"cksum of file {req.file_name} couldn't be calculated ")
            return False

        # attempt to create directory for the client files if not already exists,
        # directory name will be the client username
        username = self.database.get_clt_username(req.clt_id)
        if not username:
            print(f"error occurred when trying to retrieve username from the database"
                  f" (usage: creating client directory) ")
            return False
        clt_files_dir_path = helper.create_dir(username)
        if clt_files_dir_path is None:
            print(f" Directory for client {clt_socket} files couldn't be created OR "
                  f"directory exists but the process raised an error")
            return False

        # attempt to store the file in the client files directory
        # overwritten file which already exists
        clt_file_path = helper.store_file(req.content, clt_files_dir_path, req.file_name)
        if clt_file_path is None:
            print(f" {req.file_name} file couldn't be created / overwritten * file request *")
            return False

        # check if there's already a File entry for the client file in the database
        # if not, attempt to store it
        if not self.database.file_exists(req.file_name, req.clt_id):
            # store file information in database, verified = 0 (false) until cksum is verified
            file_entry = database.File(req.clt_id, req.file_name, clt_file_path, verified=0)
            if not self.database.store_file(file_entry):
                print(f" {req.file_name} file couldn't be stored in the database * file request *")
                return False
        print(f"{req.file_name} file from client ID {req.clt_id} successfully stored in the database * file request * ")

        # attempt to send the appropriate response
        res.header.payload_size = networkProtocol.CLT_ID_SIZE + 4 + networkProtocol.FILE_NAME_SIZE + 4
        res.clt_id = req.clt_id
        res.content_size = req.content_size
        res.file_name = req.file_name
        res.cksum = cksum
        try:  # {maybe check if need to validate all was sent}
            clt_socket.send(res.pack())
        except Exception as e:
            print(
                f"failed to send response to {clt_socket} * file request *")  # ???????????????????????????????????????????
            return False
        print(f"successfully sent response * file request *")
        return True

    def req_crc(self, data, clt_socket):
        """ handle type CRC request (valid/ not valid/ 4th time not valid"""
        req = networkProtocol.ReqCRC()
        res = networkProtocol.ResConfirmMsg()
        if not req.unpack(data):
            print(f"failed to unpack CRC type request data")
            return False
        try:
            if not self.database.clt_id_exists(req.clt_id):
                print(f"client ID {req.clt_id} not exists ")
                return False
        except Exception as e:
            print(f"failed to connect to the database")
            return False

        # handle the valid case / 4th time not valid case - need to send response confirm msg and
        # update file Verification in the database (valid case) or delete the file from client file directory (4th..)
        if req.header.req_code == networkProtocol.REQ_VALID_CRC or req.header.req_code == networkProtocol.REQ_4NVALID_CRC:
            if req.header.req_code == networkProtocol.REQ_VALID_CRC:
                if not self.database.set_file_verify(1, req.clt_id, req.file_name):
                    print(f"*CRC Valid request* couldn't update file verification in the database")
                    return False
            else:  # 4th time not valid CRC, we shall attempt to delete the file
                # remove from database
                if not self.database.remove_file(req.clt_id, req.file_name):
                    print(f"*CRC 4TH Time not valid* cannot remove file {req.file_name} from the database")
                    return False
                # delete file from client file directory
                username = self.database.get_clt_username(req.clt_id)
                if not username:
                    print(
                        f"*CRC 4TH Time not valid* cannot retrieve client username for file {req.file_name} deletion ")
                    return False
                if not helper.delete_file(username + "/" + req.file_name):
                    print(f"*CRC 4TH Time not valid* cannot delete file {req.file_name} ")
                    return False

            try:  # {maybe check if need to validate all was sent}
                clt_socket.send(res.pack())
            except Exception as e:
                print(
                    f"failed to send response to {clt_socket} * CRC valid / 4th time not valid *")
                return False
            print(f"successfully sent response * confirm msg (Valid CRC / 4th time not valid) *")

        # handle not valid case - need to send response confirm msg + start another file request handling
        elif req.header.req_code == networkProtocol.REQ_NVALID_CRC:
            try:  # {maybe check if need to validate all was sent}
                clt_socket.send(res.pack())
            except Exception as e:
                print(
                    f"failed to send response to {clt_socket} * CRC valid / 4th time not valid request *")
                return False
            print(f"successfully sent response * confirm msg (CRC not valid request) *")

            # after sending confirm msg response, client should try to send the file again.
            req_file_data = clt_socket.recv(Server.DEFAULT_RECV_SIZE)
            if not req_file_data:
                print(f" failed to receive first chunk of request file data * CRC not valid request *")
                return False
            if not self.req_file(req_file_data, clt_socket):
                print(f" Request file failed * CRC not valid request *")
                return False
        else:
            print(f" couldn't start the handling of any CRC type request (code not match) {clt_socket}")
            return False

        return True
