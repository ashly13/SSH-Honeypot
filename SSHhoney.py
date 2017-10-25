from twisted.conch import avatar, recvline
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implements


class SSHDemoProtocol(recvline.HistoricRecvLine):
	def __init__(self, user):
		self.user = user
	
	def connectionMade(self):
		recvline.HistoricRecvLine.connectionMade(self)
		self.terminal.write("Welcome to my SSH server.\n")
		self.showPrompt()
		return

	def showPrompt(self):
		self.terminal.write("$ ")
	
	def getCommandFunc(self, cmd):
		return getattr(self, 'do_' + cmd, None)

	def lineReceived(self, line):
		line = line.strip()
		func = None
		if line:
			cmdAndArgs = line.split()
			cmd = cmdAndArgs[0]
			args = cmdAndArgs[1:]
			func = self.getCommandFunc(cmd)
		if func:
			try:
				func(*args)
			except Exception, e:
				self.terminal.write("Error: %s" % e)
				self.terminal.nextLine()
		else:
			self.terminal.write("No such command.")
			self.terminal.nextLine()
			self.showPrompt()
	
	def do_help(self):
		publicMethods = filter(
		lambda funcname: funcname.startswith('do_'), dir(self))
		commands = [cmd.replace('do_', '', 1) for cmd in publicMethods]
		self.terminal.write("Commands: " + " ".join(commands))
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
		self.terminal.write("Thanks for playing!")
		self.terminal.nextLine()
		self.terminal.loseConnection()

	def do_clear(self):
		self.terminal.reset()
		self.showPrompt()


class SSHDemoAvatar(avatar.ConchUser):
	implements(ISession)

	def __init__(self, username):
		avatar.ConchUser.__init__(self)
		self.username = username
		self.channelLookup.update({'session': session.SSHSession})

	def openShell(self, protocol):
		serverProtocol = insults.ServerProtocol(SSHDemoProtocol, self)
		serverProtocol.makeConnection(protocol)
		protocol.makeConnection(session.wrapProtocol(serverProtocol))

	def getPty(self, terminal, windowSize, attrs):
		return None

	def execCommand(self, protocol, cmd):
		raise NotImplementedError()

	def closed(self):
		pass



class SSHDemoRealm(object):
	implements(portal.IRealm)

	def requestAvatar(self, avatarId, mind, *interfaces):
		if IConchUser in interfaces:
			return interfaces[0], SSHDemoAvatar(avatarId), lambda: None
		else:
			raise NotImplementedError("No supported interfaces found.")


class SSHChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse):
		
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
sshFactory.portal = portal.Portal(SSHDemoRealm())

# Setup the server's public and private keys
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {'ssh-rsa': pubKey}
sshFactory.privateKeys = {'ssh-rsa': privKey}

# Define username and password combos that will allow access to our shell
users = {'admin': 'aaa'}

# Register our Credentials Checker
sshFactory.portal.registerChecker(SSHChecker(users))

# Run the reactor server loop
reactor.listenTCP(2222, sshFactory)
reactor.run()
