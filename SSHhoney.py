from twisted.conch import avatar, recvline
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implements

# Implementation of our SSH Protocol
class SSHProtocol(recvline.HistoricRecvLine):

	def __init__(self, user):
		self.user = user
		self.commands = ["help", "echo", "whoami", "quit", "clear"]
	
	# Display banner when login attempt succeeds
	def connectionMade(self):
		recvline.HistoricRecvLine.connectionMade(self)
		self.terminal.write("Welcome to my SSH server.\n")
		self.showPrompt()

	# Display the shell prompt
	def showPrompt(self):
		self.terminal.write("$ ")

	# Process every line received from the user
	def lineReceived(self, line):

		# Log everything a user types
		try:
			lfile = open("./CommandLogs.csv", 'a')
			lfile.write(line + "\n")
			lfile.close()
		except IOError:
			pass

		line = line.strip()
		
		# Check if the given command has been implemented
		if line.split(" ")[0] not in self.commands:
			self.terminal.write("Command not found.")
			self.terminal.nextLine()
			self.showPrompt()
		else:	# Otherwise execute that function
			func = getattr(self, 'do_' + line.split(" ")[0], None)
			try:
				args = line.split(" ")[1 : ]
				func(*args)
			except Exception, e:
				self.terminal.write("Error: %s" % e)
				self.terminal.nextLine()
	
	def do_help(self):
		self.terminal.write("Commands: " + " ".join(self.commands))
		self.terminal.nextLine()
		self.showPrompt()

	def do_echo(self, *args):
		self.terminal.write(" ".join(args))
		self.terminal.nextLine()
		self.showPrompt()

	def do_whoami(self):
		self.terminal.write(self.user.username)
		self.terminal.nextLine()
		self.showPrompt()

	def do_quit(self):
		self.terminal.nextLine()
		self.terminal.loseConnection()

	def do_clear(self):
		self.terminal.reset()
		self.showPrompt()


class SSHAvatar(avatar.ConchUser):
	implements(ISession)

	def __init__(self, username):
		avatar.ConchUser.__init__(self)
		self.username = username
		self.channelLookup.update({'session': session.SSHSession})

	def openShell(self, protocol):
		serverProtocol = insults.ServerProtocol(SSHProtocol, self)
		serverProtocol.makeConnection(protocol)
		protocol.makeConnection(session.wrapProtocol(serverProtocol))

	def getPty(self, terminal, windowSize, attrs):
		return None

	def execCommand(self, protocol, cmd):
		raise NotImplementedError()

	def closed(self):
		pass



class SSHRealm(object):
	implements(portal.IRealm)

	def requestAvatar(self, avatarId, mind, *interfaces):
		if IConchUser in interfaces:
			return interfaces[0], SSHAvatar(avatarId), lambda: None
		else:
			raise NotImplementedError("No supported interfaces found.")


class SSHCredentialsChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse):
		
	def __init__(self, users):
		self.authorizedUsers = users	# Username and password combos that will allow access to our shell

	
	def requestAvatarId(self, credentials):
		#print credentials.username, credentials.password

		# Save all login attempts to file
		try:
			lfile = open("./LoginLogs.csv", 'a')
			lfile.write(credentials.username + ", " + credentials.password + "\n")
			lfile.close()
		except IOError:
			pass

		# User authentication is implemented below	
		if self.authorizedUsers.get(credentials.username) == None:
			return failure.Failure(UnauthorizedLogin)	# Authentication failure

		elif self.authorizedUsers.get(credentials.username) == credentials.password:
			return credentials.username	# Authentication success

		else:
			return failure.Failure(UnauthorizedLogin)	# Authentication failure


# Keys were generated using ssh-keygen command
def getRSAKeys():
	with open('./.ssh/key') as privateBlobFile:
		privateBlob = privateBlobFile.read()
		privateKey = keys.Key.fromString(data=privateBlob)
	with open('./.ssh/key.pub') as publicBlobFile:
		publicBlob = publicBlobFile.read()
		publicKey = keys.Key.fromString(data=publicBlob)
	return publicKey, privateKey


# Initialize Twisted's protocol factory
sshFactory = factory.SSHFactory()
sshFactory.portal = portal.Portal(SSHRealm())

# Setup the server's public and private keys
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {'ssh-rsa': pubKey}
sshFactory.privateKeys = {'ssh-rsa': privKey}

# Define username and password combos that will allow access to our shell
# Let it be empty for all attempts to be failed
users = {'user': 'p@$$w0rd'}

# Register our Credentials Checker
sshFactory.portal.registerChecker(SSHCredentialsChecker(users))

# Run the reactor server loop
reactor.listenTCP(2222, sshFactory)
reactor.run()
