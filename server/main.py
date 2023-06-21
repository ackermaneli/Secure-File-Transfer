"""
TransferIt server
main.py
description: Server execution
"""
import server
import helper


def main():
    port = helper.acquire_port("port.info")  # if can't acquire port use a default port (1234 in time writing this)
    svr = server.Server('', port)
    if not svr.svr_startup():
        print("server couldn't finish appropriately, server will stop now ")
        exit(1)


if __name__ == '__main__':
    main()
