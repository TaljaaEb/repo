import socket, ssl, sys, os
import hashlib

clients = []
verified = None

sys.argv.append('79.72.81.190')
sys.argv.append('192.168.101.107')

#HOST, PORT = 'localhost', 8900
AUTH, APORT = str(sys.argv[1]), 8443
HOST, PORT, CERT, KEY = str(sys.argv[2]), 8443, 'cert.pem', 'key.pem'

def auth():
    print('in auth-1')
    sock = socket.socket(socket.AF_INET)
    #context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context = ssl._create_unverified_context()
    context.load_cert_chain(keyfile=KEY, certfile=CERT)  # 1. key, 2. cert, 3. intermediates
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    conn = context.wrap_socket(sock, server_hostname=HOST)
    try:
        conn.connect((AUTH, APORT))
        handle(conn, clients)
        code = conn.recv(4)
    finally:
        print(code)
        if code == 'CTRU':
            print(code)
            conn.close()
        else:
            conn.close()

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
   
def handle(conn, clients):
    verify = False
    if len(clients) == 0:
        #conn.write(b'GET / HTTP/1.1\n')
        #conn.write(b'%s' % conn.getpeername()[0].encode())
        BSTRING = LOCAL_IP + LOCAL_USER
        BSTRING_ENC = hashing(BSTRING)
        conn.write(b'%s' % BSTRING_ENC.encode())
        print(BSTRING_ENC)
        clients.append(BSTRING_ENC)
        ASTRING = conn.recv().decode()
        ASTRING_ENC = hashing(ASTRING)
        print(ASTRING_ENC)
        clients.append(ASTRING_ENC)
        #print(conn.recv().decode())
    else:
        conn.write(b'%s' % clients[0].encode())
        conn.write(b'%s' % clients[1].encode())
        clients = []
        verify = True
        print(verify)

def main(args=None):
    sock = socket.socket(socket.AF_INET)
    #context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context = ssl._create_unverified_context()
    context.load_cert_chain(keyfile=KEY, certfile=CERT)  # 1. key, 2. cert, 3. intermediates
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    conn = context.wrap_socket(sock, server_hostname=HOST)
    try:
        conn.connect((HOST, PORT))
        handle(conn, clients)
    finally:
        conn.close()

if __name__ == '__main__':
    REMOTE_IP = str(sys.argv[1])
    LOCAL_IP = get_ip()
    LOCAL_USER = get_username()
    main()
    if len(clients) == 2:
        auth()

