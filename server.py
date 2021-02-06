# Python 3
# Usage: python3 server.py serverPort blockDuration timeout
# coding: utf-8
from socket import *
from threading import Thread, Timer
import time
import datetime as dt
import sys
import re
from datetime import datetime

# initial check to ensure correct number of arguments given
if (len(sys.argv) != 4):
    sys.exit('Incorrect arguments givens')

# assigning the server port number, block duration and timeout duration from the given arguments
serverPort = int(sys.argv[1])
blockDuration = int(sys.argv[2])
timeout = int(sys.argv[3])

# we create some dictionaries to keep track of current connections, 
# login history of the server, offline message deliveries,
# users blackedlisted by another user and addresses for each client
loginHistory = {}
connections = {}
offlineDeliveries = {}
blacklistedUsers = {}
addresses = {}

# we also maintain a list of all users blocked from logging on
blockedUsers = []

# the main method for handling the server's welcoming socket
def main():

    # here we create the server socket, which utilises IPv4 and TCP
    serverSocket = socket(AF_INET, SOCK_STREAM)

    # we also set some options for the TCP socket
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # next we bind the given port number to the server's socket, so any packets sent to this address will be directred to this socket
    serverSocket.bind(('', serverPort))

    # we want the server socket to listen for any client connection requests
    serverSocket.listen(5)

    # here we enter an infinite loop
    while True:

        # when a client knocks on this door, a new socket is created that is dedicated to this particular client
        client, address = serverSocket.accept()

        # upon setting up this new connection, we want to take note of the
        # port used by this client to welcome new private connections
        privatePort = client.recv(2048)
        privatePort = int(privatePort.decode())

        # for this new client socket, we create a thread and start it
        Thread(target = validateUsername, args = (client, address, privatePort)).start()

# validates the client's username
def validateUsername(client, address, privatePort):

    # we prompt for the client to enter their username
    message = 'Username: '

    # and then send this prompt to the client socket
    client.send(message.encode())

    # upon receiving a response, we store this in a variable and decode it
    response = client.recv(2048)
    response = response.decode()

    # to verify this username exists, we open the credentials file
    credentials = open('credentials.txt', 'r')

    # we now loop through each line of this credentials file,
    # keeping track of whether it exists through a variable
    isValid = False
    for line in credentials:

        # for the current line, we use regex to search for a matching pattern
        match = re.search('^({0}) (.*)$'.format(response), line)
        
        if match:
            # if a match was found, we can set the isValid variable as true
            isValid = True

            # we also extract the matched username and password into variables for later use
            username = match.group(1)
            password = match.group(2)

            # finally we can stop searching through the credentials file so we break
            break
    
    # since we are done searching the credentials file, we can close it
    credentials.close()

    if isValid:
        # if the username was valid, we now want to validate the password for this client
        validatePassword(client, address, username, password, privatePort)
    else:
        # if this valid was invalid, we notify the client that it was incorrect
        message = 'Invalid Username. Please try again\n'
        client.send(message.encode())

        # we then restart this method to give the client another attempt at entering a valid username
        validateUsername(client, address, privatePort)

# validates the client's password
def validatePassword(client, address, username, password, privatePort):

    loginStatus = False
    for i in range(3):

        # this prompt for the client to enter their password
        # also has the entered username appended in the first part,
        # as this allows the client to identify their username if successful
        # in logging in
        message = 'password: {} msg: Password: '.format(username)

        # and then send this prompt to the client socket
        client.send(message.encode())

        # upon receiving a response, we store this in a variable and decode it
        response = client.recv(2048)
        response = response.decode()

        # since we already checked the credentials file earlier, we simply check if this response matches the password
        if (response == password):

            # if this user is currently blocked, we notify the user and break
            if username in blockedUsers:
                message = 'Your account is blocked due to multiple login failures. Please try again later\n'
                break
            
            # if this user is already online, we notify the user and break
            elif username in connections:
                message = 'This account is already logged in elsewhere. Please logout and try again\n'    
                break

            # otherwise, we can set the login status as true, notify the user and break
            else:
                message = 'Welcome to the greatest messaging application ever!\n'
                client.send(message.encode())
                loginStatus = True
                break
        else:

            # if we are yet to have 3 consecutive failed login attempts, we simply notify the user it was incorrect and continue
            if (i < 2):
                message = 'Invalid Password. Please try again\n'
                client.send(message.encode())
            
            # otherwise the user is blocked, so we notify them
            else:
                message = 'Invalid Password. Your account has been blocked. Please try again later\n'

                # to block this user, we add their username to a list of blocked user and start a timer for the block duration..
                # upon finishing, the lambda function simply removes their name from this list so they can try again
                blockedUsers.append(username)
                Timer(blockDuration, lambda block: blockedUsers.remove(username), args = [username]).start()
                break
    
    # if we were successful in logging in, we call another helper function
    if loginStatus:
        home(client, address, username, password, privatePort)
    
    # otherwise, we alert the client to close their terminal
    else:
        # we send the error message to the client
        client.send(message.encode())

        # we also want to close the connection to the client socket
        client.close()

# handles client functionality once logged in
def home(client, address, username, password, privatePort):

    # once logged in, we add this username to the list of logged in users
    loginHistory[username] = True

    # additionally, we want to send a presence broadcast to all other users online
    presenceBroadcast = '{0} logged in\n'.format(username)
    for user in connections:
        # since blocked users don't get presence notifications, we also check for this before sending
        if not(user in blacklistedUsers and username in blacklistedUsers[user]):
            connections[user].send(presenceBroadcast.encode())
    
    # after notifying all other users, we can also add the current connection to this list
    connections[username] = client

    # upon logging on, we also want to check if there are any
    # offline messages stored for us. If so, we display them to the user
    if username in offlineDeliveries:
        for message in offlineDeliveries[username]:
            client.send(message.encode())
        del offlineDeliveries[username]

    # finally, we need to add the address of this client to the addresses dictionary,
    # with this being in the form of the IP address and port number
    addresses[username] = [address[0], privatePort]
    
    try:

        # since timeout is only relevant for logged in users, it is set here
        client.settimeout(timeout)

        # we now enter an infinite loop
        while True:
            
            # we wait to receive a response from the client
            response = client.recv(2048)
            
            # if we don't receive a response, we raise an error
            if not response:
                raise error('Client timeout')
            else:

                response = response.decode()

                # if the user messages to logout, we also raise an error to be handles by the except section
                if response == 'logout':
                    raise error('Client logout')

                # if the client sends the whoelse command, we send the usernames of all other
                # currently online users to them
                if response == 'whoelse':
                    for user in connections:
                        if user != username:
                            client.send((user + '\n').encode())
                    continue
                
                # if the client uses the message <user> <message> command,
                # we send this message to the user through the server
                match = re.search(r'^message (\S+) (.*)$', response)
                if match:

                    # we extract the user and message to be sent
                    user = match.group(1)
                    message = match.group(2)

                    # we also format this message ready to be sent to the intended user
                    formattedMessage = '{}: {}\n'.format(username, message)

                    # if user is self, we display an error message
                    if user == username:
                        message = 'Error. Cannot message self\n'
                        client.send(message.encode()) 
                    # if user is blocked, display message to notify this
                    elif username in blacklistedUsers and user in blacklistedUsers[username]:
                        message = 'Your message could not be delivered as the recipient has blocked you\n'
                        client.send(message.encode())
                    # if user is online, we send the message immediately
                    elif user in connections:
                        connections[user].send(formattedMessage.encode())
                    # otherwise if user is offline, we store for offline delivery
                    else:
                        # we first want to scan the credentials file to ensure this user exists
                        credentials = open('credentials.txt', 'r')
                        
                        exists = False
                        for line in credentials:
                            
                            # if we found the user in the credentials file, it is valid and
                            # we can stop searching
                            match = re.search('^{} .*$'.format(user), line)                         
                            if match:
                                exists = True
                                break

                        credentials.close()
                        
                        # if the user exists, we can now store the message until they next appear online
                        if exists:
                            # we store the messages in a dictionary of offline deliveries
                            if user in offlineDeliveries:    
                                offlineDeliveries[user].append(formattedMessage)
                            else:
                                offlineDeliveries[user] = [formattedMessage]
                        # if the user doesn't exist, we display an appropriate error message
                        else:
                            message = 'Error. Invalid user\n'
                            client.send(message.encode())
                        
                    continue
                
                # if the client uses the broadcast <message> command,
                # we send this message to all other online users
                match = re.search('^broadcast (.*)$', response)
                if match:
                    # we extract the message to be broadcasted
                    message = match.group(1)

                    # also the broadcast message is formatted ready to be sent
                    broadcast = '{}: {}\n'.format(username, message)
                    
                    # we now send this broadcast message to all currently online users
                    someBlocked = False
                    for user in connections:
                        # if the user is blocked, we don't send the message and keep track that
                        # a message could not be sent
                        if username in blacklistedUsers and user in blacklistedUsers[username]:
                            someBlocked = True
                        # we also cannot broadcast to ourself
                        elif user != username:
                            connections[user].send(broadcast.encode())
                    
                    # if we couldn't broadcast to a user because they are blocked,
                    # we notify the client
                    if someBlocked:
                        message = 'Your message could not be delivered to some recipients\n'
                        client.send(message.encode())
                    
                    continue

                # if the client uses the whoelsesince <time> command,
                # we display a list of all users logged in at any time
                # within the past <time> seconds
                match = re.search('^whoelsesince ([0-9]+)$', response)
                if match:
                    # we first extract the given time in seconds
                    seconds = int(match.group(1))

                    # we also get the current time to compare with login times for each user
                    currentTime = datetime.now()

                    # we now scan through all users who have logged in during the server's history
                    for user in loginHistory:
                        # given the user isn't ourself
                        if user != username:
                            # if the user is currently logged in, or they were logged in within the given time period,
                            # we display their username to the client
                            if loginHistory[user] == True or (currentTime - loginHistory[user]).total_seconds() < seconds:
                                client.send((user + '\n').encode())
                    continue
                
                # if the client enters the block <user> command, we want to ensure the
                # blocked user cannot send messages to the client
                match = re.search(r'^block (\S+)$', response)
                if match:

                    # we first extract the user's name to be blocked
                    user = match.group(1)

                    # since we cannot block ourself, an error message is displayed
                    if user == username:
                        message = 'Error. Cannot block self\n'
                        client.send(message.encode())
                    # otherwise, we want to ensure this user exists
                    else:

                        # we do this by scanning the credentials file
                        credentials = open('credentials.txt', 'r')
                        
                        exists = False
                        for line in credentials:
                            
                            # if the user was found in the credentials file, they are valid
                            # and we can stop searching
                            match = re.search('^{} .*$'.format(user), line)                         
                            if match:
                                exists = True
                                break

                        credentials.close()
                        
                        # if this is a valid user, we can now block them
                        if exists:
                            # the user is blocked by being added to a dictionary of blocked users
                            if user in blacklistedUsers:    
                                blacklistedUsers[user].append(username)
                            else:
                                blacklistedUsers[user] = [username]
                            
                            # we also notify the client that the user was blocked successfully
                            message = '{} is blocked\n'.format(user)
                            client.send(message.encode())
                        # if the user doesn't exist, we display an appropriate error message
                        else:
                            message = 'Error. Invalid user\n'
                            client.send(message.encode())
                    continue
                
                # if the client uses the unblock <user> command,
                # we want to unblock the user who was previously blocked by the client
                match = re.search(r'^unblock (\S+)$', response)
                if match:

                    # we extract the user's name to unblock
                    user = match.group(1)

                    # we cannot unblock ourself, so we display an error message
                    if user == username:
                        message = 'Error. Cannot unblock self\n'
                        client.send(message.encode())
                    # otherwise, we make sure this user exists before unblocking them
                    else:

                        # this is done by looking through the credentials file
                        credentials = open('credentials.txt', 'r')

                        exists = False
                        for line in credentials:
                            # if we found the user in the credentials file, we can stop searching
                            # as they are valid
                            match = re.search('^{} .*$'.format(user), line)                         
                            if match:
                                exists = True
                                break

                        credentials.close()
                        
                        # if the user exists, we can now try unblocking them
                        if exists:
                            # if the user is already blocked by the client, we simply remove them
                            # from the dictionary of blocked users and notify the client
                            if user in blacklistedUsers and username in blacklistedUsers[user]:    
                                blacklistedUsers[user].remove(username)
                                message = '{} is unblocked\n'.format(user)
                                client.send(message.encode())
                            # if the user wasn't blocked by the client, we cannot unblock them,
                            # so we display an error message
                            else:
                                message = 'Error. {} was not blocked\n'.format(user)
                                client.send(message.encode())
                        # if the user doesn't exist, we display an appropriate error message
                        else:
                            message = 'Error. Invalid user\n'
                            client.send(message.encode())
                    continue
                
                # if the client uses the startprivate <user> command, we want
                # to commence p2p messaging with the user
                match = re.search(r'^startprivate (\S+)$', response)
                if match:

                    # we extract the user from this command
                    user = match.group(1)

                    # if user is self, we display an error message
                    if user == username:
                        message = 'Error. Cannot private message self\n'
                        client.send(message.encode()) 
                    # if user is blocked, display message to notify this
                    elif username in blacklistedUsers and user in blacklistedUsers[username]:
                        message = 'Cannot commence private messaging as the recipient has blocked you\n'
                        client.send(message.encode())
                    # if user is online, we can attempt to setup private messaging
                    elif user in connections:

                        # the first part of our message contains the IP address
                        # port number for this user, so a TCP connection can be established.
                        # The second segment is a confirmation message to be displayed to the client
                        message = 'startprivate: {} {} {} msg: Start private messaging with {}\n'.format(addresses[user][0], addresses[user][1], user, user)
                        client.send(message.encode())

                    # otherwise if user is offline, we check whether they exist or not
                    else:
                        # we first want to scan the credentials file to ensure this user exists
                        credentials = open('credentials.txt', 'r')
                        
                        exists = False
                        for line in credentials:
                            
                            # if we found the user in the credentials file, it is valid and
                            # we can stop searching
                            match = re.search('^{} .*$'.format(user), line)                         
                            if match:
                                exists = True
                                break

                        credentials.close()
                        
                        # if the user exists, we notify the client we cannot initiate private messaging
                        # as they are offline
                        if exists:
                            message = 'Cannot start private messaging since {} is offline\n'.format(user)
                        # if the user doesn't exist, we display an appropriate error message
                        else:
                            message = 'Error. Invalid user\n' 
                        client.send(message.encode())
                    continue

                # if the client uses the stopprivate <user> command, this indicates the user
                # wishes to discontinue private messaging with user
                match = re.search(r'^stopprivate (\S+)$', response)
                if match:

                    # we first extract the user from this command
                    user = match.group(1)

                    # our message is then split into two parts, with the first containing the name of the user to
                    # close the private connection with, and the second segment having the message to display to the
                    # other user
                    message = 'stopprivate: {} msg: Private messaging with {} has ended\n'.format(user, username)
                    client.send(message.encode())
                    
                    continue

                # if the response doesn't match any of the above commands, it is unknown
                message = 'Error. Invalid command\n'
                client.send(message.encode())              
    except:

        # if an exception is raised, the connection to the client socket is closed
        client.close()

        # next we remove this connection from the list of all connections
        del connections[username]

        # a presence broadcast to all other active users notifying them we have logged out
        presenceBroadcast = '{0} logged out\n'.format(username)
        for user in connections:
            # since blocked users don't get presence notifications, we also check for this before sending
            if not(user in blacklistedUsers and username in blacklistedUsers[user]):
                connections[user].send(presenceBroadcast.encode())
    
        # finally we note when this user logged out in the onlineUsers dictionary
        loginHistory[username] = datetime.now()

# since all functionality is handled within seperate helper functions,
# we simply call main and the server starts
main()