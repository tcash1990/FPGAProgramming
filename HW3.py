# CSCE 44303/54203 Homework 3 (Programming)
# I. Task Description
# In this assignment, you will implement encrypted communications between two parties, Alice
# and Bob, and evaluate the performance of AES and RSA under different parameters. For
# simplicity, Alice and Bob will be simulated by two programs running on the same computer.
# When Alice sends a message to Bob, she writes the message to a file; Bob receives the message
# through reading from the file. (If you know socket/network programming, you can also directly
# implement socket/network communications between the two.)
# Part 1: Implement encryption and decryption using AES with 128-bit key. Assume that Alice
# and Bob already have a shared secret key k (e.g., they can read the key from the same file). Alice
# encrypts an 18-byte message m (the message is manually input from command line), and writes
# the ciphetext into a file named ctext. Bob reads the ciphertext from the file, decrypts it, and prints
# the message m. The encryption should use the CBC mode.
# Part 2: Implement encryption and decryption using RSA with 2048-bit key. Assume that Alice
# already has got Bob’s public key (you need to figure out a way to do this). Alice encrypts an 18-
# byte message m (the message is manually input from command line) using Bob’s public key, and
# writes the ciphetext into a file named ctext. Bob reads the ciphertext from the file, decrypts it,
# and prints the message m.

# CSCE 44303/54203 Homework 3 (Programming)
# I. Task Description
# In this assignment, you will implement encrypted communications between two parties, Alice
# and Bob, and evaluate the performance of AES and RSA under different parameters. For
# simplicity, Alice and Bob will be simulated by two programs running on the same computer.
# When Alice sends a message to Bob, she writes the message to a file; Bob receives the message
# through reading from the file. (If you know socket/network programming, you can also directly
# implement socket/network communications between the two.)
# Part 1: Implement encryption and decryption using AES with 128-bit key. Assume that Alice
# and Bob already have a shared secret key k (e.g., they can read the key from the same file). Alice
# encrypts an 18-byte message m (the message is manually input from command line), and writes
# the ciphetext into a file named ctext. Bob reads the ciphertext from the file, decrypts it, and prints
# the message m. The encryption should use the CBC mode.
# Part 2: Implement encryption and decryption using RSA with 2048-bit key. Assume that Alice
# already has got Bob’s public key (you need to figure out a way to do this). Alice encrypts an 18-
# byte message m (the message is manually input from command line) using Bob’s public key, and
# writes the ciphetext into a file named ctext. Bob reads the ciphertext from the file, decrypts it,
# and prints the message m.


# Step 1: Alice encrypts 18-byte message m - writes ciphertext into file ctext
# Step 2: Bob reads ciphertext from file ctext - decrypts and prints message m
import time
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def writeAESKey(bits = 128):
    key = get_random_bytes(bits//8)
    if bits == 128:
        writefile(key, "aes128_key.bin", is_binary=True)
    elif bits == 192:
        writefile(key, "aes192_key.bin", is_binary=True)
    elif bits == 256:
        writefile(key, "aes256_key.bin", is_binary=True)
    return key

def encryptAES(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    initialVector = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    ciphertext = b64encode(initialVector + ciphertext) #.decode('utf-8'))
    writefile(ciphertext, "aes_ctext.txt", is_binary=True)
    return ciphertext

def decryptAES(ciphertext, key):
    cipherData = b64decode(ciphertext)
    initialVector = cipherData[:AES.block_size]
    ciphertext = cipherData[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, initialVector)
    message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return message.decode('utf-8')

def writeRSAKey(bits = 2048):
    keyPair = RSA.generate(bits)
    private_key = keyPair.export_key()
    public_key = keyPair.public_key().export_key()
    if bits == 2048:
        writefile(private_key, "rsa_private_key.pem", is_binary=True)
        writefile(public_key, "rsa_public_key.pem", is_binary=True)
    elif bits == 1024:
        writefile(private_key, "rsa1024_private_key.pem", is_binary=True)
        writefile(public_key, "rsa1024_public_key.pem", is_binary=True)
    elif bits == 4096:
        writefile(private_key, "rsa4096_private_key.pem", is_binary=True)
        writefile(public_key, "rsa4096_public_key.pem", is_binary=True)

def encryptRSA(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher_rsa.encrypt(message.encode('utf-8'))
    encoded_ciphertext = b64encode(ciphertext).decode('utf-8')  #
    writefile(encoded_ciphertext, "rsa_ctext.txt") 
    return encoded_ciphertext

def decryptRSA(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher_rsa.decrypt(b64decode(ciphertext))
    return decrypted.decode('utf-8')

def readfile(filename, is_binary=False):
    mode = "rb" if is_binary else "r"
    with open(filename, mode) as file:
        return file.read()

def writefile(data, filename, is_binary=False):
    mode = "wb" if is_binary else "w"
    with open(filename, mode) as file:
        if is_binary:
            file.write(data)
        else:
            file.write(data)

def getKey(filename):
    if filename.endswith('.pem'):
        return readfile(filename, is_binary=False)
    return readfile(filename, is_binary=True)

def main():

    
    key128 = writeAESKey()
    key192 = writeAESKey(192)
    key256 = writeAESKey(256)
    writeRSAKey(1024)
    writeRSAKey(2048)
    writeRSAKey(4096)
    userselection = 0
    while(userselection != 9):

        print("Make a selection: \n1. Encrypt with AES \n2. Decrypt with AES \n3. Encrypt with RSA\
              \n4. Decrypt with RSA \n5. Check AES Performance \n6. Check RSA performance \n9. Exit\n")
        userselection = int(input())
        if userselection == 9:
            break
        if userselection == 1:
            userMessage = input("Enter the message you would like to encrypt: ")
            key = getKey("aes128_key.bin")
            ciphertext = encryptAES(userMessage, key)
            time.sleep(1)
            print("Message encrypted successfully")
            time.sleep(1)
            print("Cipher text: " + str(ciphertext))
            time.sleep(2)
            
            
        if userselection == 2:
            print("Checking for messages...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(1)
            key = getKey("aes128_key.bin")
            ciphertext = readfile("aes_ctext.txt")
            message = decryptAES(ciphertext, key)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(1)
            print("Decrypting....\n....\n...")
            time.sleep(2)
            print("Message Found: ")
            print(message)
            time.sleep(3)
            
        if userselection == 3:
            userMessage = input("Enter the message you would like to encrypt: ")
            key = getKey("rsa_public_key.pem")
            ciphertext = encryptRSA(userMessage, key)
            time.sleep(1)
            print("Message encrypted successfully")
            time.sleep(1)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(2)
            writefile (ciphertext, "rsa_ctext.txt")
            time.sleep(3)
            
        if userselection == 4:
            print("Checking for messages...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(1)
            key = getKey("rsa_private_key.pem")
            ciphertext = readfile("rsa_ctext.txt")
            message = decryptRSA(ciphertext, key)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(1)
            print("Decrypting....\n....\n...")
            time.sleep(2)
            print("Message Found: ")
            time.sleep(1)
            print(message)
            time.sleep(3)

# Part 3: Measure the performance of AES and RSA under different parameters. This is to explore
# how the key size affects the computation cost of AES and RSA. Take a 7-byte message manually
# input from command line. Implement AES with 128-bit, 192-bit, and 256-bit keys. For each key
# size, run the encryption over the 7-byte message and decryption of its ciphertext for one hundred
# times, measure the average time needed for one encryption, and measure the average time
# needed for one decryption. Implement RSA with 1024-bit, 2048-bit, and 4096-bit keys. For each
# key size, run the encryption over the 7-byte message and decryption of its ciphertext for one
# hundred times, measure the average time needed for one encryption, and measure the average
# time needed for one decryption. Print the average time of encryption and the average time of
# decryption for each key size for AES and RSA.

        if userselection == 5:
            userMessage = input("Enter a 7-byte message:")
           
            totalEncryptionTime = 0
            totalDecryptionTime = 0

            currentTime = time.time()
            print("Testing AES 128 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key128)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key128)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)

            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))
            

            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing AES 192 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key192)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key192)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))


            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing AES 256 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key256)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key256)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))

        if userselection == 6:
            userMessage = input("Enter a 7-byte message:")
            
            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing RSA 1024 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa1024_public_key.pem")
                privateKey = getKey("rsa1024_private_key.pem")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))
        
            totalEncryptionTime = 0
            totalDecryptionTime = 0        
            currentTime = time.time()
            print("Testing RSA 2048 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa_public_key.pem")
                privateKey = getKey("rsa_private_key.pem")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))

            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing RSA 4096 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa4096_public_key.pem")
                privateKey = getKey("rsa4096_private_key.pem")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))    

main()       
# Step 1: Alice encrypts 18-byte message m - writes ciphertext into file ctext
# Step 2: Bob reads ciphertext from file ctext - decrypts and prints message m
import time
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def writeAESKey(bits = 128):
    key = get_random_bytes(bits//8)
    if bits == 128:
        writefile(key, "aes128_key.txt", is_binary=True)
    elif bits == 192:
        writefile(key, "aes256_key.txt", is_binary=True)
    elif bits == 256:
        writefile(key, "aes512_key.txt", is_binary=True)
    return key

def encryptAES(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    initialVector = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    ciphertext = b64encode(initialVector + ciphertext) #.decode('utf-8'))
    writefile(ciphertext, "aes_ctext.txt", is_binary=True)
    return ciphertext

def decryptAES(ciphertext, key):
    cipherData = b64decode(ciphertext)
    initialVector = cipherData[:AES.block_size]
    ciphertext = cipherData[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, initialVector)
    message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return message.decode('utf-8')

def writeRSAKey(bits = 2048):
    keyPair = RSA.generate(bits)
    private_key = keyPair.export_key()
    public_key = keyPair.public_key().export_key()
    if bits == 2048:
        writefile(private_key, "rsa_private_key.txt", is_binary=True)
        writefile(public_key, "rsa_public_key.txt", is_binary=True)
    elif bits == 1024:
        writefile(private_key, "rsa1024_private_key.txt", is_binary=True)
        writefile(public_key, "rsa1024_public_key.txt", is_binary=True)
    elif bits == 4096:
        writefile(private_key, "rsa4096_private_key.txt", is_binary=True)
        writefile(public_key, "rsa4096_public_key.txt", is_binary=True)

def encryptRSA(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher_rsa.encrypt(message.encode('utf-8'))
    encoded_ciphertext = b64encode(ciphertext).decode('utf-8')  #
    writefile(encoded_ciphertext, "rsa_ctext.txt") 
    return encoded_ciphertext

def decryptRSA(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher_rsa.decrypt(b64decode(ciphertext))
    return decrypted.decode('utf-8')

def readfile(filename, is_binary=False):
    mode = "rb" if is_binary else "r"
    with open(filename, mode) as file:
        return file.read()

def writefile(data, filename, is_binary=False):
    mode = "wb" if is_binary else "w"
    with open(filename, mode) as file:
        if is_binary:
            file.write(data)
        else:
            file.write(data)

def getKey(filename):
    return readfile(filename, is_binary=True)

def main():
    
    key128 = writeAESKey()
    key192 = writeAESKey(192)
    key256 = writeAESKey(256)
    writeRSAKey(1024)
    writeRSAKey(2048)
    writeRSAKey(4096)
    userselection = 0
    while(userselection != 9):

        print("Make a selection: \n1. Encrypt with AES \n2. Decrypt with AES \n3. Encrypt with RSA\
              \n4. Decrypt with RSA \n5. Check AES Performance \n6. Check RSA performance \n9. Exit\n")
        userselection = int(input())
        if userselection == 9:
            break
        if userselection == 1:
            userMessage = input("Enter the message you would like to encrypt: ")
            key = getKey("aes128_key.txt")
            ciphertext = encryptAES(userMessage, key)
            time.sleep(1)
            print("Message encrypted successfully")
            time.sleep(1)
            print("Cipher text: " + str(ciphertext))
            time.sleep(2)
            #writefile (ciphertext, "ctext") 
            
        if userselection == 2:
            print("Checking for messages...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(1)
            key = getKey("aes128_key.txt")
            ciphertext = readfile("aes_ctext.txt")
            message = decryptAES(ciphertext, key)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(1)
            print("Decrypting....\n....\n...")
            time.sleep(2)
            print("Message Found: ")
            print(message)
            time.sleep(3)
            
        if userselection == 3:
            userMessage = input("Enter the message you would like to encrypt: ")
            key = getKey("rsa_public_key.txt")
            ciphertext = encryptRSA(userMessage, key)
            time.sleep(1)
            print("Message encrypted successfully")
            time.sleep(1)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(2)
            writefile (ciphertext, "rsa_ctext.txt")
            time.sleep(3)
            
        if userselection == 4:
            print("Checking for messages...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(.5)
            print("...\n")
            time.sleep(1)
            key = getKey("rsa_private_key.txt")
            ciphertext = readfile("rsa_ctext.txt")
            message = decryptRSA(ciphertext, key)
            print("Ciphertext: " + str(ciphertext))
            time.sleep(1)
            print("Decrypting....\n....\n...")
            time.sleep(2)
            print("Message Found: ")
            time.sleep(1)
            print(message)
            time.sleep(3)

# Part 3: Measure the performance of AES and RSA under different parameters. This is to explore
# how the key size affects the computation cost of AES and RSA. Take a 7-byte message manually
# input from command line. Implement AES with 128-bit, 192-bit, and 256-bit keys. For each key
# size, run the encryption over the 7-byte message and decryption of its ciphertext for one hundred
# times, measure the average time needed for one encryption, and measure the average time
# needed for one decryption. Implement RSA with 1024-bit, 2048-bit, and 4096-bit keys. For each
# key size, run the encryption over the 7-byte message and decryption of its ciphertext for one
# hundred times, measure the average time needed for one encryption, and measure the average
# time needed for one decryption. Print the average time of encryption and the average time of
# decryption for each key size for AES and RSA.

        if userselection == 5:
            userMessage = input("Enter a 7-byte message:")
           
            totalEncryptionTime = 0
            totalDecryptionTime = 0

            currentTime = time.time()
            print("Testing AES 128 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key128)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key128)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)

            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))
            

            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing AES 192 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key192)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key192)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))


            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing AES 256 bit:...\n...")
            for i in range(1,100):
                elapsedEncryptionTime = time.time()
                ciphertext = encryptAES(userMessage,key256)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptAES(ciphertext,key256)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))

        if userselection == 6:
            userMessage = input("Enter a 7-byte message:")
            
            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing RSA 1024 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa1024_public_key.txt")
                privateKey = getKey("rsa1024_private_key.txt")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))
        
            totalEncryptionTime = 0
            totalDecryptionTime = 0        
            currentTime = time.time()
            print("Testing RSA 2048 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa_public_key.txt")
                privateKey = getKey("rsa_private_key.txt")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))

            totalEncryptionTime = 0
            totalDecryptionTime = 0
            currentTime = time.time()
            print("Testing RSA 4096 bit:...\n...")
            for i in range(1,100):
                publicKey = getKey("rsa4096_public_key.txt")
                privateKey = getKey("rsa4096_private_key.txt")
                elapsedEncryptionTime = time.time()
                ciphertext = encryptRSA(userMessage, publicKey)
                totalEncryptionTime = totalEncryptionTime + (elapsedEncryptionTime - currentTime)
                elapsedDecryptionTime = time.time()
                decryptRSA(ciphertext,privateKey)
                totalDecryptionTime = totalDecryptionTime + (elapsedDecryptionTime - currentTime)
            newTime = time.time() - currentTime
            print("Time Elapsed: " + str(newTime))
            print("Average Encryption Time = " + str((totalEncryptionTime/100)))
            print("Average Decryption Time = " + str((totalDecryptionTime/100)))    

main()       