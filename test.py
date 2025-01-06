import http.server
import ssl
import socket, ssl, sys, os
import hashlib

clients = []
connection = []
HOST, PORT, CERT, KEY = '0.0.0.0', 8443, '/etc/ssl/certs/cert.pem', '/etc/ssl/private/key.pem'

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    IP = s.getsockname()[0]
    s.close()
    return IP

def get_username():
    USER = os.getlogin()
    return USER

def hashing(ctext):
    obj = hashlib.sha256()
    obj.update(bytes(ctext, 'utf-8'))
    return obj.hexdigest()

def match(conn):
    print(len(clients))
    if len(connection) == 2:
        conn.write(b'%s' % "CTRU".encode())
        connection[0].write(b'%s' % "CTRU".encode())
        return True

def handle(conn, clients):
    #print(conn.recv())
    BSTRING = conn.recv()
#    BSTRING_ENC = hashing(str(BSTRING))
    logger.debug(BSTRING)
    clients.append(BSTRING)
    #conn.write(b'HTTP/1.1 200 OK\n\n%s' % conn.getpeername()[0].encode())
    #conn.write(b'%s' % conn.getpeername()[0].encode())
    #ASTRING = LOCAL_IP + LOCAL_USER
    #conn.write(b'%s' % ASTRING.encode())
    #ASTRING_ENC = hashing(ASTRING)
    #logger.debug(ASTRING_ENC)
    # client in 0 server in 1 | client in 2 server in 3
    var = match(conn)
    if var:
#        connection = [connection.pop(0) for item in list(connection)]
#            print(connection[0],connection[1],connection[2],connection[3]) 
             #connection[2].write(b'%s' % "CTRU".encode())
             #connection[3].write(b'%s' % "CTRU".encode())
        logger.debug(str(clients[0]))
        logger.debug(str(clients[1]))
#         logger.debug(str(clients[2]))
#         logger.debug(str(clients[3]))
        clients = []
        var = False
        connection = [] 

def main():
    i = 0
    sock = socket.socket()
    sock.bind((HOST, PORT))
    sock.listen(5)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(keyfile="server.key", certfile="server.crt")  # 1. key, 2. cert, 3. intermediates
    #context.load_cert_chain(keyfile=KEY, certfile=CERT, password='auth')  # 1. key, 2. cert, 3. intermediates
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
    while True:
        conn = None
        ssock, addr = sock.accept()
        try:
            conn = context.wrap_socket(ssock, server_side=True)
            connection.append(conn)
	    #      handle(conn, clients)
            handle(connection[i], clients)
            i += 1
        except ssl.SSLError as e:
            print(e)
        finally:
            if conn:
                conn.close()
                pass


def mmmm():
    # Set up the handler and server
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(('0.0.0.0', 8443), handler)
    # Wrap the server with SSL
    httpd.socket = ssl.wrap_socket(httpd.socket,
                               keyfile="server.key",
                               certfile="server.crt", 
                               server_side=True)

    print("Server started at https://localhost:8443")
    httpd.serve_forever()

if __name__ == '__main__':
    import logging
    import sys

    logging.basicConfig(format='%(asctime)s \n%(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    logger.addHandler(h)
#    logger.debug('- - - - - - - - - -'+'\n')     
    #REMOTE_IP = str(sys.argv[1])
    LOCAL_IP = get_ip()
    LOCAL_USER = get_username()
    main()