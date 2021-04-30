# Python-Envcrypto

Python-Envcrypto allows you to safely store your environment variables in your code repository.

## Installation

```bash
pip3 install envcrypto
```

## Usage

```python
api_secret = 'AABB.Fufu@TEST001'
env_name = 'APP_API_SECRET'
my_key = b'\02S\n\t@k\x02'  # Any type and any length
print('''
Set environment variable in your OS:
    export {0}={1}
In your code:
    data = {2!r}'''.format(
    env_name,
    set_environ(env_name, api_secret, my_key),
    get_environ(env_name, key=my_key),
))

print('''
Set environment variable in your OS (if key is None):
    export {0}={1}
In your code:
    data = {2!r}
'''.format(
    env_name,
    set_environ(env_name, api_secret),
    get_environ(env_name),
))

print('default value:', get_environ('NOT_EXIST', default='default.value'))
```

Output:

```shell
Set environment variable in your OS:
    export APP_API_SECRET=hzONuFZreUEDDRoHC20GJ7bkDDKGN1Mj4lcqn9osqGU=
In your code:
    data = 'AABB.Fufu@TEST001'

Set environment variable in your OS (if key is None):
    export APP_API_SECRET=AABB.Fufu@TEST001
In your code:
    data = 'AABB.Fufu@TEST001'

default value: default.value
```

## Extension methods

```python
# Some additional extension methods
any_data = 123.45
any_key = False

print('use key:', AESCipher(any_key).key)
print('use iv:', AESCipher(any_key).iv)
print('encrypted:', AESCipher(any_key).encrypt_aes_cbc(any_data))
print('encrypted:', encrypt_aes_cbc(any_data, any_key))
print('decrypted:', AESCipher(any_key).decrypt_aes_cbc(b'\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_'))
print('decrypted:', decrypt_aes_cbc(b'\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_', any_key))
print()

my_data = 0x1011010
my_key = 0o3334444
my_iv = b'iv\f123'
print(encrypt_aes_cbc(my_data, my_key, my_iv))
# b'16846864'
print(decrypt_aes_cbc(b'\x0b*\xf3\x90\x1a\x84.\xed\x1e\xf8\xb1\xce\x1c\xf7\xe9\xc0', my_key, my_iv))

my_data = 'Fufu .$\x0f\r\ni^★地99'
my_key = b'ff\xf4YF7777777\x024\x66~\xa7\xb6\x5c12356'

a = encrypt(my_data, my_key)
b = decrypt(a, my_key)
# a:'57s0iy0Z2LqiQ9tq9Js2zozWhgLxpmEcGiRVylG9Ank='
# b:'Fufu .$\x0f\r\ni^★地99'
# b==my_data:True
print('\na:{0!r}\nb:{1!r}\nb==my_data:{2!r}'.format(a, b, b == my_data))

# encrypt aes-cbc
ciphertext_bytes = encrypt_aes_cbc(my_data, my_key)
ciphertext_hex = encrypt_aes_cbc_hex(my_data, my_key)
ciphertext_b64 = encrypt_aes_cbc_b64(my_data, my_key)
ciphertext_urlsafeb64 = encrypt_aes_cbc_urlsafe_b64(my_data, my_key)
# bytes:b'\xbb\xff#z\x95\xcb7*\x8d\xca\x00\x1e\xb7\xcaN\xf8S\x05\xe5\x80\xcb\x9d#dr\xb6vp\xf6\xe0\x9c\x96'
# hex:bbff237a95cb372a8dca001eb7ca4ef85305e580cb9d236472b67670f6e09c96
# b64:u/8jepXLNyqNygAet8pO+FMF5YDLnSNkcrZ2cPbgnJY=
# urlsafeb64:u_8jepXLNyqNygAet8pO-FMF5YDLnSNkcrZ2cPbgnJY=
print('\nbytes:{}\nhex:{}\nb64:{}\nurlsafeb64:{}'.format(
    ciphertext_bytes, ciphertext_hex, ciphertext_b64, ciphertext_urlsafeb64))

# decrypt aes-cbc
plaintext_1 = decrypt_aes_cbc(ciphertext_bytes, my_key)
plaintext_2 = decrypt_aes_cbc_hex(ciphertext_hex, my_key)
plaintext_3 = decrypt_aes_cbc_b64(ciphertext_b64, my_key)
plaintext_4 = decrypt_aes_cbc_urlsafe_b64(ciphertext_urlsafeb64, my_key)
# b'Fufu .$\x0f\r\ni^\xe2\x98\x85\xe5\x9c\xb099'
# 'Fufu .$\x0f\r\ni^★地99'
# 'Fufu .$\x0f\r\ni^★地99'
# 'Fufu .$\x0f\r\ni^★地99'
# True
print('\n{0!r}\n{1!r}\n{2!r}\n{3!r}\n{4}'.format(
    plaintext_1, plaintext_2, plaintext_3, plaintext_4, plaintext_4 == my_data))
```





*ff*