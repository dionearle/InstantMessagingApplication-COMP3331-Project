# Python 3
# Usage: python3 client.py serverIP serverPort
# coding: utf-8
from socket import *
from threading import Thread
import sys
import re

# initial check to ensure correct number of arguments given
if (len(sys.argv) != 3):
    sys.exit('Incorrect arguments givens')

# assigning the server IP address and server port number from the given arguments
serverIP = sys.argv[1]
serverPort = int(sys.argv[2])

# we also use a dictionary to store all private connections this client has
privateConnections = {}

# finally we have a global variable to keep track of the clien't username once logged in
username = ''

# the main method which sets up the client socket and its threads
def main():

    # first we create the client socket, which utilises IPv4 and TCP
    clientSocket = socket(AF_INET, SOCK_STREAM)

    # next the TCP connection with the server must be established using a three-way handshake
    clientSocket.connect((serverIP, serverPort))

    # first, we create a thread for the welcoming socket for any incoming private connections
    Thread(target = privateThread, args = [clientSocket], daemon = True).start()

    # we now create a seperate thread responsible for sending messages to the server
    Thread(target = sendThread, args=[clientSocket], daemon = True).start()

    # and finally call a function to start receiving messages from the server
    recvThread(clientSocket)

# handles any messages to be sent from the client
def sendThread(client):

    # we enter an infinite loop
    while True:

        # we first get the user's input
        message = input()

        # the only case we check for here is whether the user is attempting to send a private message
        # to another user, which is initiated by the private <user> <message> command
        match = re.search(r'^private (\S+) (.*)$', message)
        if match:

            # we first extract the user and message from the command
            user = match.group(1)
            message = match.group(2)

            # if we have not already setup a private connection with this client,
            # an error message is displayed
            if not user in privateConnections:
                print('Error. Private messaging to {} not enabled'.format(user))
            # otherwise, we attempt to send the message privately through our already established 
            # private connection with the other client
            else:
                try:
                    formattedMessage = '{}(private): {}\n'.format(username, message)
                    privateConnections[user].send(formattedMessage.encode())
                # if the user is no longer online at this address, then an exception will be raised and we display an error message
                except:
                    del privateConnections[user]
                    print('Error. {} is no longer available through this connection'.format(user))
        # otherwise if it didn't match the private message command, we simply send our inputted messaeg
        # to the server
        else:
            client.send(message.encode())

# handles any messages received from the server
def recvThread(client):

    global username

    # we enter an infinite loop
    while True:

        # we first wait for a message from the server and store it in a variable
        response = client.recv(2048)

        # if a message is not received, we break from the loop
        if not response:
            break

        response = response.decode()

        # if we receieved a password message, this means the username
        # we entered was valid, so we want to store this as this client's username
        match = re.search(r'^password: (\S*) msg: (.*)$', response)
        if match:

            # we simply extract the username and the message to display
            username = match.group(1)
            response = match.group(2)

        # if we receive a startprivate message, we need to take some extra steps
        # before displaying the message to the client
        match = re.search(r'^startprivate: (\S+) (\S+) (\S+) msg: (.*)$', response)
        if match:

            # first we extract the IP address, port , user and message from this command
            privateIP = match.group(1)
            privatePort = int(match.group(2))
            user = match.group(3)
            response = match.group(4) + '\n'

            # here we create the private socket, which utilises IPv4 and TCP
            p2pSocket = socket(AF_INET, SOCK_STREAM)

            # next the TCP connection with the other client must be established using a three-way handshake
            p2pSocket.connect((privateIP, privatePort))

            # after setting the private connection up, we want to let the other client know our username
            p2pSocket.send(username.encode())

            # we then associate this user with the socket connected to their machine
            privateConnections[user] = p2pSocket

            # we also want to create a seperate thread to handle messages receieved from the other client
            Thread(target = recvThread, args=[p2pSocket], daemon = True).start()

        # if we receive a stopprivate message, we want to attempt to close a private connection with another client
        match = re.search(r'^stopprivate: (\S+) msg: (.*)$', response)
        if match:

            # we first extract the user and message from the command
            user = match.group(1)
            response = match.group(2) + '\n'

            # if there was not already an active p2p messaging session with <user>,
            # an error message should be displayed
            if not user in privateConnections:
                response = 'Error. Cannot stop private messaging as an active connection with {} does not exist\n'.format(user)
            # otherwise we close the TCP connection between the two end points
            else:
                # we first send a message to the other client alerting them private messaging has finished
                privateConnections[user].send(response.encode())
                
                # we then close the private connection to the client
                privateConnections[user].close()
                del privateConnections[user]

                continue
        
        # if another client closed a private connection through the above block of code,
        # we will receive a message of this format alerting us that this occured.
        # Upon receieving this message, we should remove this connection
        # from our list of private connections with other clients
        match = re.search(r'^Private messaging with (\S+) has ended$', response)
        if match:
            user = match.group(1)
            del privateConnections[user]
        
        # finally we display this received message to the client
        print(response, flush = True, end = '')

    # finally we close the client socket
    client.close()

    # when logging out, we also need to close all private connections
    for user in privateConnections:
        privateConnections[user].close()

# handles the setup of a private messaging TCP connection with another client
def privateThread(clientSocket):

    # here we create the private welcoming socket, which utilises IPv4 and TCP
    privateSocket = socket(AF_INET, SOCK_STREAM)

    # we also set some options for the TCP socket
    privateSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # next we bind this socket to a random unused port number
    privateSocket.bind(('', 0))

    # we want the welcoming socket to listen for any client connection requests
    privateSocket.listen(5)

    # before we start listening for incoming connections, we want to send the welcoming
    # socket's port number to the server so other client's can connect to this socket
    message = '{}'.format(privateSocket.getsockname()[1])
    clientSocket.send(message.encode())

    # here we enter an infinite loop
    while True:

        # when a client knocks on this door, a new socket is created that is dedicated to this particular client
        client, address = privateSocket.accept()

        # after setting up this private connection, the client
        # who initiated this connection should also send their username
        # so we can associate this socket with a user
        response = client.recv(2048)
        response = response.decode()
        privateConnections[response] = client

        # finally we create a seperate thread to handle messages receieved from the other client
        Thread(target = recvThread, args=[client], daemon = True).start()

# since all functionality is handled within seperate helper functions,
# we simply call main and the server starts
main()
