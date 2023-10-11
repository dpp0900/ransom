from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

FTP_HOST = '0.0.0.0'
FTP_PORT = 9021
FTP_UPLOAD_DIR = '/home/ransom/ftp/upload'
FTP_DOWNLOAD_DIR = '/home/ransom/ftp/download'

def main():
    auth = DummyAuthorizer()
    auth.add_anonymous(FTP_UPLOAD_DIR, perm="ewm")
    auth.add_user('down','loader',FTP_DOWNLOAD_DIR, perm="er")
    handler = FTPHandler
    handler.authorizer = auth

    handler.passive_ports = range(9000, 9100)

    address = (FTP_HOST, FTP_PORT)
    server = FTPServer(address, handler)
    server.max_cons = 256
    server.max_cons_per_ip = 5

    server.serve_forever()

if __name__ == '__main__':
    main()