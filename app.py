import time
import hashlib
import json
from random import randint
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Transaction:
    def __init__(self, amount, payer, payee):
        self.amount = amount
        self.payer = payer
        self.payee = payee

    def __str__(self):
        return str(vars(self))

class Block:
    nonce = randint(0,999999999)
    def __init__(self, prevHash, transaction):
        self.prevHash = prevHash
        self.transaction = transaction
        self.ts = time.time()

    def getHash(self):
        strObject = str(vars(self)).encode("utf-8")
        print(strObject)
        hashObject = hashlib.sha1(strObject).hexdigest()
        return hashObject

    def __str__(self):
        return str(vars(self))

class Chain(metaclass=Singleton):
    def __init__(self):
        self.chain = [Block(None,Transaction(100, 'genesis', 'satoshi'))]

    def getLastBlock(self):
        return self.chain[-1]
    
    def addBlock(self, transaction, senderPublicKey, signature):
        isValid = False
        try:
            senderPublicKey.verify(signature, transaction.__str__().encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            isValid = True
        except InvalidSignature:
            isValid = False
        finally:
            if isValid:
                newBlock = Block(self.getLastBlock().getHash(), transaction)
                self.mine(newBlock.nonce)
                self.chain.append(newBlock)

    def mine(self, nonce):
        solution = 1
        print('⛏ mining')
        while True:
            hashNum = hashlib.md5(str(nonce+solution).encode('utf-8')).hexdigest()
            if hashNum[:4] == '0000':
                return solution
            solution+=1
    
    def __str__(self):
        strChain = []
        for block in self.chain:
            strBlock = {"prevHash":block.prevHash, "transaction":block.transaction.__str__(), "ts":block.ts}
            strChain.append(strBlock)
        return str(strChain)
        

class Wallet:
    def __init__(self):
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )
        self.key = key
        self.privateKey = private_key
        self.publicKey = public_key
        self.publicKeyObject = key.public_key()
    
    def sendMoney(self, amount, payeePublicKey):
        transaction = Transaction(amount, self.publicKey, payeePublicKey)
        signature = self.key.sign(transaction.__str__().encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        chain.addBlock(transaction, self.publicKeyObject, signature)

chain = Chain()
satoshi = Wallet()
bob = Wallet()
alice = Wallet()

satoshi.sendMoney(50, satoshi.publicKey)
bob.sendMoney(23, alice.publicKey)
alice.sendMoney(5, bob.publicKey)

print(chain)