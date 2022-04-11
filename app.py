import json, shutil, time
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

#testing AES and ChaCha20 crypto algorithms using blank 100 MB and 1 GB files to measure time
    #no latency or throughput testing necessary as all executions are local
#file generation in Win CMD:
    #FSUTIL FILE CREATENEW test_100mb.txt 104857600
    #FSUTIL FILE CREATENEW test_1gb.txt 1048576000

class AES_Encryption:
    def __init__(self):
        self.input_file = shutil.copyfile(input('Enter filename: '), 'aes_copy')
        self.key = pad(b'mykey', AES.block_size)
        self.iv = pad(b'myiv', AES.block_size)
        with open(self.input_file, 'r') as file: self.input_contents = file.read()
        
        self.aes_time = time.gmtime(0)
        self.output(self.decrypt(self.encrypt(self.input_contents)))

    def encrypt(self, input_contents):
        try:
            self.data_bytes = bytes(input_contents, 'utf-8')
            self.padded_bytes = pad(self.data_bytes, AES.block_size)
            self.AES_obj = AES.new(self.key, AES.MODE_CBC, self.iv)
            self.cipher_text = self.AES_obj.encrypt(self.padded_bytes)
            
            print('-- AES ENCRYPTION SUCCESS --')
            print('-- AES CIPHER: '+ str(self.cipher_text))
        
        except(ValueError, KeyError):
            print('-- AES ENCRYPTION FAILURE --')

        return self.cipher_text

    def decrypt(self, encrypted_file):
        try:
            self.AES_obj = AES.new(self.key, AES.MODE_CBC, self.iv)
            self.raw_bytes = self.AES_obj.decrypt(encrypted_file)
            self.extracted_bytes = unpad(self.raw_bytes, AES.block_size).decode('ascii')
            self.aes_time = time.time()
            
            if self.extracted_bytes == self.input_contents:
                print('-- AES DECRYPTION SUCCESS --')

        except(ValueError, KeyError):
            print('-- AES DECRYPTION FAILURE --')
        
        return self.extracted_bytes

    def output(self, decrypted_file):
        self.output_file = open('aes_decrypt.txt', 'w')
        self.output_file.seek(0)
        self.output_file.write(decrypted_file)
        self.output_file.truncate()

class CC20_Encryption:
    def __init__(self):
        self.input_file = shutil.copyfile(input('Enter filename: '), 'cc20_copy')
        self.key = get_random_bytes(32)
        with open(self.input_file, 'r') as file: self.input_contents = file.read()
        
        self.cc20_time = time.gmtime(0)
        self.output(self.decrypt(self.encrypt(self.input_contents)))

    def encrypt(self, input_contents):
        try:
            self.cipher = ChaCha20.new(key = self.key)
            self.cipher_text = self.cipher.encrypt(bytes(input_contents, 'utf-8'))
            self.b64_nonce = b64encode(self.cipher.nonce).decode('utf-8')
            self.b64_cipher_text = b64encode(self.cipher_text).decode('utf-8')
            self.result = json.dumps({'nonce':self.b64_nonce, 'cipher_text':self.b64_cipher_text})

            print('-- CC20 ENCRYPTION SUCCESS --')
            print('-- CC20 CIPHER: '+ str(self.cipher_text))
        
        except(ValueError, KeyError):
            print('-- CC20 ENCRYPTION FAILURE --')

        return self.result

    def decrypt(self, encrypted_file):
        try:
            self.b64 = json.loads(encrypted_file)
            self.nonce = b64decode(self.b64['nonce'])
            self.cipher_text = b64decode(self.b64['cipher_text'])
            self.cipher = ChaCha20.new(key = self.key, nonce = self.nonce)
            self.decrypted_file = self.cipher.decrypt(self.cipher_text).decode('utf-8')
            self.cc20_time = time.time()

            if self.decrypted_file == self.input_contents:
                print('-- CC20 DECRYPTION SUCCESS --')

        except (ValueError, KeyError):
            print("-- CC20 DECRYPTION FAILURE --")
    
        return self.decrypted_file

    def output(self, decrypted_file):
        self.output_file = open('cc20_decrypt.txt', 'w')
        self.output_file.seek(0)
        self.output_file.write(decrypted_file)
        self.output_file.truncate()

def main():
    AES_Obj = AES_Encryption()
    CC20_Obj = CC20_Encryption()
    
    print('AES Time: ', AES_Obj.aes_time / 1e9, '(s)') #conversion from nanoseconds to seconds
    print('CC20 Time: ', CC20_Obj.cc20_time / 1e9, '(s)')

    #Results generated via testing 100MB and 1GB files indicate that files approximately 1GB and below have no effect on (encryption + decryption) time for either algorithm, producing a rounded average of 1.64 seconds for all tests

if __name__ == '__main__':
    main()