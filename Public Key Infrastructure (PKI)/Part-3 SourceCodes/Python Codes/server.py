import sys, socket, ssl, select, getopt, pprint 
PORT = 5555

CERT_FILE = "/home/michail/work5/client1/sslTalk/trail/CSE.crt"
KEY_FILE = "/home/michail/work5/client1/sslTalk/trail/CSE.key"
TRUSTED_FILE = "/home/michail/work5/client1/sslTalk/trail/trustChain.pem"

def doServerWork():
    SOCKET_LIST = []
    context = ssl.create_default_context()

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE, password="1234")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(TRUSTED_FILE)

    ssl_sock = socket.socket()
    ssl_sock.bind(('', PORT))
    ssl_sock.listen(5)

    SOCKET_LIST.append(sys.stdin)

    print "Chat server started on port " + str(PORT)

    while True:
        newsocket, fromaddr = ssl_sock.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)

        SOCKET_LIST.append(connstream)
        try:
            while True:
                ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
            
                for sock in ready_to_read:
                    if sock == sys.stdin: # user entered a message
                        try:
                            msg = sys.stdin.readline()
                            connstream.write(msg)
                            sys.stdout.write('[Me]:' + str(msg)); sys.stdout.flush()
                        except:
                            continue

                    else: # a message from a client, not a new connection
                        try:
                            data = connstream.read()
                            if data:
                                sys.stdout.write('[Client]: ' + str(data)); sys.stdout.flush()
                        except:
                            continue

        finally:
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()
            break


def main(argv):
    global PORT
    for arg in argv:
        PORT = int(arg)
        break

    doServerWork()

if __name__ == "__main__":
   main(sys.argv[1:])
