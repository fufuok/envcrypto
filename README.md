# Python-Envcrypto

Python-Envcrypto allows you to safely store your environment variables in your code repository.

envcrypto~=v0.1.0:

- After `bytes` encryption and decryption, return `bytes`. `<In: bytes, Out: bytes>`
- After other data types are encrypted and decrypted, return `str`: `str(raw_data)`. `<In: other, Out: str>`
- After encryption and decryption fails, return `None`.

## Installation

```bash
pip3 install envcrypto
```

## Usage


```python
# Recommended usage
api_secret = 'AABB.Fufu@TEST001'
env_name = 'APP_API_SECRET'
my_key = b'\02S\n\t@k\x02'  # Any type and any length
set_res = set_environ(env_name, api_secret, my_key)
get_res = get_environ(env_name, key=my_key)
print('''Raw data[{0}]: {1!r}
Set environment variable in your OS:
    export {2}={3}
In your code (result is string):
    result = get_environ(env_name, key=my_key)
    result[{4}] == api_secret == {5!r}
'''.format(type(api_secret), api_secret, env_name, set_res, type(get_res), get_res))

# if key is None
set_res = set_environ(env_name, api_secret)
get_res = get_environ(env_name)
print('''Raw data[{0}]: {1!r}
Set environment variable in your OS (if key is None):
    export {2}={3}
In your code (result is string):
    result = get_environ(env_name)
    result[{4}] == api_secret == {5!r}
'''.format(type(api_secret), api_secret, env_name, set_res, type(get_res), get_res))

# if raw data is bytes
secret_bytes = b'a random bytes \xff&\xd2...'
set_res = set_environ(env_name, secret_bytes, my_key)
get_res = get_environ(env_name, key=my_key)
print('''Raw data[{0}]: {1!r}
Set environment variable in your OS:
    export {2}={3}
In your code (result is bytes):
    result = get_environ(env_name, key=my_key)
    result[{4}] == secret_bytes == {5!r}
'''.format(type(secret_bytes), secret_bytes, env_name, set_res, type(get_res), get_res))

print('No default value:', get_environ('NOT_EXIST'))
print('Has a default value:', get_environ('NOT_EXIST', default='default.value'))
```

Output:

```shell
Raw data[<class 'str'>]: 'AABB.Fufu@TEST001'
Set environment variable in your OS:
    export APP_API_SECRET=c5wi7F_2XsRSqp1DngONW7abeP0WgEY47hzbnBxMT_Rd
In your code (result is string):
    result = get_environ(env_name, key=my_key)
    result[<class 'str'>] == api_secret == 'AABB.Fufu@TEST001'

Raw data[<class 'str'>]: 'AABB.Fufu@TEST001'
Set environment variable in your OS (if key is None):
    export APP_API_SECRET=AABB.Fufu@TEST001
In your code (result is string):
    result = get_environ(env_name)
    result[<class 'str'>] == api_secret == 'AABB.Fufu@TEST001'

Raw data[<class 'bytes'>]: b'a random bytes \xff&\xd2...'
Set environment variable in your OS:
    export APP_API_SECRET=Yu3LPc_Alf3KhTAhDXOd9VdEGcNmy5DSIwCLf00qPa9Q
In your code (result is bytes):
    result = get_environ(env_name, key=my_key)
    result[<class 'bytes'>] == secret_bytes == b'a random bytes \xff&\xd2...'

No default value: None
Has a default value: default.value
```

## Extension methods

```python
# Some additional extension methods
bytes_data = b'Hello bytes'
any_key = False
en_res = encrypt(bytes_data, any_key)
de_res = decrypt(en_res, any_key)
# en_res[<class 'str'>] = 'YjVMkROX3hNyt9mEJfwBvfI='
# de_res[<class 'bytes'>] == bytes_data[<class 'bytes'>] == b'Hello bytes'
print('en_res[{0}] = {1!r}\n'
      'de_res[{2}] == bytes_data[{3}] == {4!r}\n'.format(type(en_res), en_res,
                                                         type(de_res), type(bytes_data), de_res))

# Not bytes, the result will be string
any_data = 123.45

# use key: b'False\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b
# \x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'
# use iv: b'False\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'
# encrypted: b's\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_'
# encrypted: b's\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_'
# decrypted: 123.45
# decrypted: 123.45
print('use key:', AESCipher(any_key).key)
print('use iv:', AESCipher(any_key).iv)
print('encrypted:', AESCipher(any_key).encrypt_aes_cbc(any_data))
print('encrypted:', encrypt_aes_cbc(any_data, any_key))
print('decrypted:', AESCipher(any_key).decrypt_aes_cbc(b's\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_'))
print('decrypted:', decrypt_aes_cbc(b's\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_', any_key))

# res[<class 'str'>] = '123.45'
res = decrypt_aes_cbc(b's\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_', any_key)
print('res[{0}] = {1!r}'.format(type(res), res))
print()

# Standard AES-CBC-128 pkcs7
my_data = b'Fufu'
my_key = b'0123456789012345'
my_iv = b'1234567890123456'
# GUV0s3zVssASrOsESlepWA==
print(b64encode(encrypt_aes_cbc(my_data, my_key, my_iv, 128)[1:]).decode('utf-8'))
print(AESCipher(my_key, my_iv, 128, 'pkcs7', with_type=False).encrypt_aes_cbc_b64(my_data))

# In: string, Out: string
my_data = 'Fufu .$\x0f\r\ni^★地99'
my_key = b'ff\xf4YF7777777\x024\x66~\xa7\xb6\x5c12356'

a = encrypt(my_data, my_key)
b = decrypt(a, my_key)
# a:'c-e7NIstGdi6okPbavSbNs6M1oYC8aZhHBokVcpRvQJ5'
# b:'Fufu .$\x0f\r\ni^★地99'
# b==my_data:True
print('\na:{0!r}\nb:{1!r}\nb==my_data:{2!r}'.format(a, b, b == my_data))

# encrypt aes-cbc
ciphertext_bytes = encrypt_aes_cbc(my_data, my_key)
ciphertext_hex = encrypt_aes_cbc_hex(my_data, my_key)
ciphertext_b64 = encrypt_aes_cbc_b64(my_data, my_key)
ciphertext_urlsafeb64 = encrypt_aes_cbc_urlsafe_b64(my_data, my_key)
# bytes:b's\xbb\xff#z\x95\xcb7*\x8d\xca\x00\x1e\xb7\xcaN\xf8S\x05\xe5\x80\xcb\x9d#dr\xb6vp\xf6\xe0\x9c\x96'
# hex:73bbff237a95cb372a8dca001eb7ca4ef85305e580cb9d236472b67670f6e09c96
# b64:c7v/I3qVyzcqjcoAHrfKTvhTBeWAy50jZHK2dnD24JyW
# urlsafeb64:c7v_I3qVyzcqjcoAHrfKTvhTBeWAy50jZHK2dnD24JyW
print('\nbytes:{}\nhex:{}\nb64:{}\nurlsafeb64:{}'.format(
    ciphertext_bytes, ciphertext_hex, ciphertext_b64, ciphertext_urlsafeb64))

# decrypt aes-cbc
plaintext_1 = decrypt_aes_cbc(ciphertext_bytes, my_key)
plaintext_2 = decrypt_aes_cbc_hex(ciphertext_hex, my_key)
plaintext_3 = decrypt_aes_cbc_b64(ciphertext_b64, my_key)
plaintext_4 = decrypt_aes_cbc_urlsafe_b64(ciphertext_urlsafeb64, my_key)
# 'Fufu .$\x0f\r\ni^★地99'
# 'Fufu .$\x0f\r\ni^★地99'
# 'Fufu .$\x0f\r\ni^★地99'
# 'Fufu .$\x0f\r\ni^★地99'
# True
print('\n{0!r}\n{1!r}\n{2!r}\n{3!r}\n{4}'.format(
    plaintext_1, plaintext_2, plaintext_3, plaintext_4, plaintext_4 == my_data))

# Generate a random key
# random_key = os.urandom(16)
random_key = AESCipher(bits=128).key
print(random_key)
```







*ff*