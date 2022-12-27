from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def Encrypt_frame(key, frame):
    aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    pad_pkcs7 = pad(frame.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypt_aes = aes.encrypt(pad_pkcs7)
    encrypt_text = str(base64.urlsafe_b64encode(encrypt_aes), encoding='utf-8')
    return encrypt_text

def Decrypt_frame(key, frame):
    aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    res = base64.urlsafe_b64decode(bytes(frame.encode(encoding='utf-8')))
    msg = str(aes.decrypt(res), encoding='utf-8').replace('\0', '');
    return msg

def pad_key(key):
    while len(key)%16 != 0:
        key += '_'
    return key

def str_xor(s: str, k: str):
    k = (k * (len(s) // len(k) + 1))[0:len(s)]
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s, k))

if __name__ == '__main__':
    key = "123456"
    text = "I'm doing 信息安全导论"
    key = pad_key(key)
    # result = Encrypt_frame(key, text)
    # print('加密结果：', result)
    # result = Decrypt_frame(key, result)
    # print('解密结果：', result)
    result = str_xor(key,text)
    print('加密结果：', result)
    result = str_xor(key, result)
    print('解密结果：', result)
