import sys, socket, ssl, pprint, getopt, select
PORT = 6666

CERT_FILE = "/home/michail/work7/sslTalk/trail/EE.crt"
KEY_FILE = "/home/michail/work7/sslTalk/trail/EE.key"
TRUSTED_FILE = "/home/michail/work7/sslTalk/trail/trustedChain.crt"

def doClientWork():

    context = ssl.create_default_context()

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE, password="1234")
    context.load_verify_locations(TRUSTED_FILE)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Require a certificate from the server. We used a self-signed certificate
    # so here ca_certs must be the server certificate itself.
    ssl_sock = context.wrap_socket(sock, server_side=False)

    ssl_sock.connect(('192.168.75.135', PORT))

    #print repr(ssl_sock.getpeername())
    #print ssl_sock.cipher()
    #print pprint.pformat(ssl_sock.getpeercert())

    socket_list = [sys.stdin, ssl_sock]
    
    #data = ssl_sock.read()
    #print data

    while True:
        # Get the list sockets which are readable
        ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])

        for sock in ready_to_read:
            if sock == ssl_sock:
                # incoming message from remote server
                data = ssl_sock.read()
                if data:
                    sys.stdout.write('[Server]: ')
                    sys.stdout.write(data); sys.stdout.flush()
            else:
                # user entered a message
                msg = sys.stdin.readline()
                ssl_sock.write(msg)
                sys.stdout.write('[Me]: ' + str(msg)); sys.stdout.flush()

    # Closing the SSL socket
    ssl_sock.close()


def main(argv):
    global PORT
    for arg in argv:
        PORT = int(arg)
        break

    doClientWork()


if __name__ == "__main__":
   main(sys.argv[1:])