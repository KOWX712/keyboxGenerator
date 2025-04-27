import os
from random import randint, choice
from base64 import b64decode
try:
	os.chdir(os.path.abspath(os.path.dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)
LB = 2 # the lower bound of the length of the device ID
UB = 12 # the upper bound of the length of the device ID
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
keyboxFormatter = """<?xml version="1.0"?>
<AndroidAttestation>
	<NumberOfKeyboxes>1</NumberOfKeyboxes>
	<Keybox DeviceID="{0}">
		<Key algorithm="ecdsa">
			<PrivateKey format="pem">
{1}
			</PrivateKey>
			<CertificateChain>
				<NumberOfCertificates>1</NumberOfCertificates>
				<Certificate format="pem">
{2}
				</Certificate>
			</CertificateChain>
		</Key>
		<Key algorithm="rsa">
			<PrivateKey format="pem">
{3}
			</PrivateKey>
		</Key>
	</Keybox>
</AndroidAttestation>"""


def canOverwrite(flags:list, idx:int, prompts:str|tuple|list|set) -> bool:
	return True

def execute(commandline:str) -> int|None:
	if isinstance(commandline, str):
		print("$ " + commandline)
		return os.system(commandline)
	else:
		return None

def handleOpenSSL(flag:bool = True) -> bool|None:
	if isinstance(flag, bool):
		errorLevel = execute("openssl version")
		if EXIT_SUCCESS == errorLevel:
			return True
		elif flag: # can try again
			execute("sudo apt-get install openssl libssl-dev")
			return handleOpenSSL(False)
		else:
			return False
	else:
		return None

def pressTheEnterKeyToExit(errorLevel:int|None = None):
	try:
		print("Please press the enter key to exit ({0}). ".format(errorLevel) if isinstance(errorLevel, int) else "Please press the enter key to exit. ")
		input()
	except:
		pass

def main() -> int:
	# Parameters #
	failureCount = 0
	deviceID = "".join([choice(CHARSET) for _ in range(randint(LB, UB))]) # or specify the device ID manually like "YourDeviceID"
	ecPrivateKeyFilePath = "ecPrivateKey.pem"
	certificateFilePath = "certificate.pem"
	rsaPrivateKeyFilePath = "rsaPrivateKey.pem"
	keyboxFilePath = "keybox.xml" # None for no files written
	flags = [not (os.path.isfile(ecPrivateKeyFilePath) or os.path.isfile(certificateFilePath)), not os.path.isfile(rsaPrivateKeyFilePath), not os.path.isfile(keyboxFilePath)]
	
	# First-phase Generation #
	if flags[0] or canOverwrite(flags, 0, (ecPrivateKeyFilePath, certificateFilePath)):
		failureCount += execute("openssl ecparam -name prime256v1 -genkey -noout -out \"{0}\"".format(ecPrivateKeyFilePath)) != 0
	if flags[0] or not os.path.isfile(certificateFilePath):
		failureCount += execute("openssl req -new -x509 -key \"{0}\" -out {1} -days 3650 -subj \"/CN=Keybox\"".format(ecPrivateKeyFilePath, certificateFilePath)) != 0
	if flags[1] or canOverwrite(flags, 1, rsaPrivateKeyFilePath):
		failureCount += execute("openssl genrsa -out \"{0}\" 2048".format(rsaPrivateKeyFilePath)) != 0
	if failureCount > 0:
		print("Cannot generate a sample ``keybox.xml`` file since {0} PEM file{1} not generated successfully. ".format(failureCount, ("s were" if failureCount > 1 else " was")))
		pressTheEnterKeyToExit(11)
		return 11
	
	# First-phase Reading #
	try:
		with open(ecPrivateKeyFilePath, "r", encoding = "utf-8") as f:
			ecPrivateKey = f.read()
		with open(certificateFilePath, "r", encoding = "utf-8") as f:
			certificate = f.read()
		with open(rsaPrivateKeyFilePath, "r", encoding = "utf-8") as f:
			rsaPrivateKey = f.read()
	except BaseException as e:
		print("Failed to read one or more of the PEM files. Details are as follows. \n{0}".format(e))
		pressTheEnterKeyToExit(12)
		return 12
	
	# Second-phase Generation #
	if flags[1]: # only updates the key content when the original key is newly generated or updating is allowed
		if rsaPrivateKey.startswith("-----BEGIN PRIVATE KEY-----") and rsaPrivateKey.rstrip().endswith("-----END PRIVATE KEY-----"):
			print("A newer openssl version is used. The RSA private key in the PKCS8 format will be converted to that in the PKCS1 format soon. ")
			failureCount += execute("openssl rsa -in \"{0}\" -out \"{0}\" -traditional".format(rsaPrivateKeyFilePath))
			if failureCount > 0:
				print("Cannot convert the RSA private key in the PKCS8 format to that in the PKCS1 format. ")
				pressTheEnterKeyToExit(13)
				return 13
			else:
				print("Finished converting the RSA private key in the PKCS8 format to that in the PKCS1 format. ")
				try:
					with open(rsaPrivateKeyFilePath, "r", encoding = "utf-8") as f:
						rsaPrivateKey = f.read()
				except BaseException as e:
					print("Failed to update the RSA private key from \"{0}\". Details are as follows. \n{1}".format(rsaPrivateKeyFilePath, e))
					pressTheEnterKeyToExit(14)
					return 14
		elif rsaPrivateKey.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") and rsaPrivateKey.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----"):
			print("An OpenSSL private key is detected, which will be converted to the RSA private key soon. ")
			failureCount += execute("ssh-keygen -p -m PEM -f \"{0}\" -N \"\"".format(rsaPrivateKeyFilePath))
			if failureCount > 0:
				print("Cannot convert the OpenSSL private key to the RSA private key. ")
				pressTheEnterKeyToExit(15)
				return 15
			else:
				print("Finished converting the OpenSSL private key to the RSA private key. ")
				try:
					with open(rsaPrivateKeyFilePath, "r", encoding = "utf-8") as f: # the ``ssh-keygen`` overwrites the file though no obvious output filepaths specified
						rsaPrivateKey = f.read()
				except BaseException as e:
					print("Failed to update the RSA private key from \"{0}\". Details are as follows. \n{1}".format(rsaPrivateKeyFilePath, e))
					pressTheEnterKeyToExit(16)
					return 16
	
	# Brief Checks #
	if not (ecPrivateKey.startswith("-----BEGIN EC PRIVATE KEY-----") and ecPrivateKey.rstrip().endswith("-----END EC PRIVATE KEY-----")):
		print("An invalid EC private key is detected. Please try to use the latest key generation tools to solve this issue. ")
		pressTheEnterKeyToExit(17)
		return 17
	if not (certificate.startswith("-----BEGIN CERTIFICATE-----") and certificate.rstrip().endswith("-----END CERTIFICATE-----")):
		print("An invalid certificate is detected. Please try to use the latest key generation tools to solve this issue. ")
		pressTheEnterKeyToExit(18)
		return 18
	if not (rsaPrivateKey.startswith("-----BEGIN RSA PRIVATE KEY-----") and rsaPrivateKey.rstrip().endswith("-----END RSA PRIVATE KEY-----")):
		print("An invalid final RSA private key is detected. Please try to use the latest key generation tools to solve this issue. ")
		pressTheEnterKeyToExit(19)
		return 19
	
	# Keybox Generation #
	ecPrivateKey_indented = "\n".join(f"				{line}" for line in ecPrivateKey.splitlines())
	certificate_indented = "\n".join(f"					{line}" for line in certificate.splitlines())
	rsaPrivateKey_indented = "\n".join(f"				{line}" for line in rsaPrivateKey.splitlines())
	
	keybox = keyboxFormatter.format(deviceID, ecPrivateKey_indented, certificate_indented, rsaPrivateKey_indented)
	print("Generated keybox with a length of {0}: ".format(len(keybox)), end="")
	print(keybox, end="")
	if keyboxFilePath is not None and (flags[2] or canOverwrite(flags, 2, keyboxFilePath)):
		try:
			with open(keyboxFilePath, "w", encoding = "utf-8") as f:
				f.write(keybox)
			print("Successfully wrote the keybox to \"{0}\". ".format(keyboxFilePath), end="")
			pressTheEnterKeyToExit(EXIT_SUCCESS)
			return EXIT_SUCCESS
		except BaseException as e:
			print("Failed to write the keybox to \"{0}\". Details are as follows. \n{1}".format(keyboxFilePath, e), end="")
			pressTheEnterKeyToExit(20)
			return 20
	else:
		print("The keybox has not been written to any files. Please refer to the text above. ", end="")
		pressTheEnterKeyToExit(EXIT_FAILURE)
		return EXIT_FAILURE



if "__main__" == __name__:
	exit(main())