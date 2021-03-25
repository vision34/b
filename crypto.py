 
import os
import io
import sys
import pandas as pd
import codecs
import hashlib
import ecdsa
import time 
import random
import secrets
import numpy as np
import os 
import string


#many thanks for blocksmyth and other 3rd party packages creators

class KeyGenerator:
    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.prng_state = None
        self.__init_pool()
        
    def seed_input(self, str_input):
        time_int = int(time.time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)
            
    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int = big_int % (self.CURVE_ORDER - 1) # key < curve order
        big_int = big_int + 1 # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time.time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0
    
    def __generate_big_int(self):
        if self.prng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.prng_state = random.getstate()
        random.setstate(self.prng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.prng_state = random.getstate()
        return big_int
class Bitcoin:
    @staticmethod
    def generate_address(private_key):
        public_key = Bitcoin.__private_to_public(private_key)
        address = Bitcoin.__public_to_address(public_key)
        return address
        
    @staticmethod
    def generate_compressed_address(private_key):
        public_key = Bitcoin.__private_to_compressed_public(private_key)
        address = Bitcoin.__public_to_address(public_key)
        return address
    
    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key
    
    @staticmethod
    def __private_to_compressed_public(private_key):
        private_hex = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Get X from the key (first half)
        key_string = key_hex.decode('utf-8')
        half_len = len(key_hex) // 2
        key_half = key_hex[:half_len]
        # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
        last_byte = int(key_string[-1], 16)
        bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
        public_key = bitcoin_byte + key_half
        return public_key
    
    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = base58(address_hex)
        return wallet

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string
     

start_time = time.time()
sec = 1 # displays the frame rate every 1 second
cycle = 0 
btc_file =os.path.dirname(__file__)+ 'btc_balance_sorted.csv'
print('basename:    ', os.path.basename(__file__)) 
 
kg = KeyGenerator()
kg.seed_input(''.join(random.choices(string.ascii_lowercase, k=256)))   
print('\n\n') 
mydata = pd.read_csv(btc_file,   usecols=  [0]  )  
#print('%s\r\n%s'%(private_key,public_key))  
#print(public_key) 
#public_keys =  np.append(mydata.values,[public_key])
public_keys =  mydata.values 
#np.append(arr1, arr2) 
import time  
indexed = pd.Index(public_keys)
#data = mydata["adress"].str.find(public_key) 
#print(np.in1d(public_keys.values, [public_key]))
pos = [-1] 
print('db loaded, started genererating')   
while(True):   
    private_key = kg.generate_key() 
    public_key =  Bitcoin.generate_compressed_address(private_key) 
    pos = indexed.get_indexer([public_key])  
    #print('{}{}'.format(pos,public_key))
    if(pos != [-1]): 
        with open('D:\BITCOIN_PRIVATE_KEY_FOUND.txt', 'a') as file: 
            file.write(private_key)
        break 
    cycle+=1
    if (time.time() - start_time) > sec:
        print("FPS: ", cycle / (time.time() - start_time))
        cycle = 0
        start_time = time.time() 
    
    
with open('D:\BITCOIN_PRIVATE_WALLET_FOUND.txt', 'a') as file:
    s = "{}\r\n{}\r\n{}".format(pos,private_key,public_key)
    file.write(s)
    
print(pos) 
#print(public_keys.isin([public_key]))
