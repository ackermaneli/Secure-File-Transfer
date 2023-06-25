"""
TransferIt server
database.py
description: this file handles the server database (creation, database operations)
"""
import networkProtocol
import sqlite3


class Database:
    """ represents the program database """

    def __init__(self, db_name):
        self.db_name = db_name

    def connect(self):
        """ attempt to connect to the database """
        conn = sqlite3.connect(self.db_name)
        conn.text_factory = bytes
        return conn

    def executescript(self, script):
        """ attempt to execute a given script """
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except Exception as e:
            pass
        conn.close()

    def execute_query(self, query, params, to_commit=False):
        """ attempt to execute a given query with a given params, return the query outcome.
        params are for parameterized queries to protect from SQL Injections """
        outcome = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            if to_commit:
                conn.commit()
                outcome = True
            else:
                outcome = cur.fetchall()
        except Exception as e:
            print(e)
        conn.close()
        return outcome

    def tables_init(self):
        """ attempt to create database tables """
        # clients table creation
        self.executescript(f"""
                    CREATE TABLE clients(
                    ID CHAR(16) PRIMARY KEY,
                    Name CHAR(255) NOT NULL, 
                    PublicKey CHAR(160),
                    LastSeen DATE, 
                    AESKey CHAR(16));
                    """)

        # files table creation
        self.executescript(f"""
                    CREATE TABLE files(
                    ID CHAR(16) NOT NULL,
                    FileName CHAR(255) NOT NULL, 
                    PathName CHAR(160) NOT NULL, 
                    Verified INTEGER CHECK(Verified = 0 or Verified = 1),
                    FOREIGN KEY(ID) REFERENCES clients(ID)); 
                    """)  # Verified value is 0 or 1 represents a boolean type (sqlite3 don't have bool)

    def clt_id_exists(self, clt_id):
        """ check if a given client id is already exists in the database """
        outcome = self.execute_query(f"SELECT * FROM clients WHERE ID = ?", [clt_id])
        if not outcome:
            return False
        return len(outcome) > 0

    def clt_username_exists(self, clt_username):
        """ check if a given client id is already exists in the database """
        outcome = self.execute_query(f"SELECT * FROM clients WHERE Name = ?", [clt_username])
        if not outcome:
            return False
        return len(outcome) > 0

    def file_exists(self, file_name, clt_id):
        """ check if a given file name is already exists in the database table files"""
        outcome = self.execute_query(f"SELECT * FROM files WHERE FileName = ? AND ID = ?", [file_name, clt_id])
        if not outcome:
            return False
        return len(outcome) > 0

    def get_clt_username(self, clt_id):
        """ given a client ID, attempt to retrieve his username from the database"""
        outcome = self.execute_query(f"SELECT Name FROM clients WHERE ID = ?", [clt_id])
        if not outcome:
            return None
        return outcome[0][0]

    def get_clt_aes_key(self, clt_id):  # ******** MAYBE DON'T NEED THIS ***********
        """ given a client ID, attempt to retrieve his aes key from the database """
        outcome = self.execute_query(f"SELECT AESKey FROM clients WHERE ID = ?", [clt_id])
        if not outcome:
            return None
        return outcome[0][0]

    def set_public_key(self, clt_id, clt_public_key):
        if not clt_public_key or len(clt_public_key) != networkProtocol.CLT_PUBLICKEY_SIZE:
            return False
        return self.execute_query(f"UPDATE clients SET PublicKey = ? WHERE ID = ? ", [clt_public_key, clt_id], True)

    def set_last_seen(self, clt_id, time):
        return self.execute_query(f"UPDATE clients SET LastSeen = ? WHERE ID = ?", [time, clt_id], True)

    def set_aes_key(self, clt_id, aes_key):
        if not aes_key or len(aes_key) != networkProtocol.CLT_SYMMETRICKEY_SIZE:
            return False
        return self.execute_query(f"UPDATE clients SET AESKey = ? WHERE ID = ?", [aes_key, clt_id], True)

    def set_file_verify(self, verified, clt_id, file_name):
        if verified != 0 and verified != 1:
            return False
        return self.execute_query(f"UPDATE files SET Verified = ? WHERE ID = ? AND FileName = ?", [verified, clt_id, file_name], True)

    def store_clt(self, clt):
        """ attempt to store a client into the 'clients' table, keys will be updated and checked in later phase """
        if not type(
                clt) is Client or not clt.check_clt_id() or not clt.check_clt_name() or not clt.check_clt_lastseen():
            return False
        return self.execute_query(f"INSERT INTO clients VALUES (?, ?, ?, ?, ?)",
                                  [clt.ID, clt.Name, clt.PublicKey, clt.LastSeen, clt.AESKey], True)

    def store_file(self, file):
        """ attempt to store a file into the 'files' table """
        if not type(file) is File or not file.check_file():
            return False
        return self.execute_query(f"INSERT INTO files VALUES (?, ? ,? ,?)",
                                  [file.ID, file.FileName, file.PathName, file.Verified], True)

    def remove_file(self, clt_id, file_name):
        """ remove a file by id and file name from the database """
        return self.execute_query(f"DELETE FROM files WHERE ID = ? AND FileName = ?", [clt_id, file_name], True)


class Client:
    """ class which represents a client entry for the database """

    def __init__(self, clt_id, clt_name, clt_public_key, last_seen, aes_key):
        self.ID = bytes.fromhex(clt_id)  # 16 bytes unique id
        self.Name = clt_name  # 255 bytes null terminated ascii string
        self.PublicKey = clt_public_key  # 160 bytes
        self.LastSeen = last_seen  # client last request date & time
        self.AESKey = aes_key  # 16 bytes symmetric key

    def check_clt_id(self):
        if not self.ID or len(self.ID) != networkProtocol.CLT_ID_SIZE:
            return False
        return True

    def check_clt_name(self):
        if not self.Name or len(self.Name) >= networkProtocol.CLT_USERNAME_SIZE:
            return False
        return True

    def check_clt_public_key(self):
        if not self.PublicKey or len(self.PublicKey) != networkProtocol.CLT_PUBLICKEY_SIZE:
            return False
        return True

    def check_clt_lastseen(self):
        if not self.LastSeen:
            return False
        return True

    def check_aes_key(self):
        if not self.AESKey or len(self.AESKey) != networkProtocol.CLT_SYMMETRICKEY_SIZE:
            return False
        return True


class File:
    """ class which represents a file entry for the database """

    def __init__(self, clt_id, file_name, path_name, verified):
        self.ID = clt_id
        self.FileName = file_name  # 255 bytes
        self.PathName = path_name  # 255 bytes
        self.Verified = verified  # boolean value (0 or 1)

    def check_file(self):
        """ check if the file attributes match the requirements """
        if not self.ID or len(self.ID) != networkProtocol.CLT_ID_SIZE:
            return False
        if not self.FileName or len(self.FileName) > networkProtocol.FILE_NAME_SIZE:
            return False
        if not self.PathName or len(self.PathName) > networkProtocol.FILE_PATH_NAME_SIZE:
            return False
        if self.Verified != 0 and self.Verified != 1:
            return False
        return True
