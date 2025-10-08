# Encryptor
Encryptor is a fast multithreaded file encryption and decryption cli tool optimized for multi-core CPUs and minimal RAM usage.

It uses OpenSSL's AES algorithm with CTR mode and chunked file reading so that only a small portion of the file is loaded into memory at a time, making it possible to encrypt very large files on systems with limited RAM.

## Installation
- Make sure to have installed OpenSSL.
    ```sh
    sudo apt-get install libssl-dev  # for Debian/Ubuntu
    # or
    brew install openssl # for MacOS
    ```
- Type `make` inside the project's root.

## Usage
### Encrypt a file
```sh
./encryptor <file_to_encrypt> <encrypted_output> <strong_password>
```
### Decrypt a file
```sh
./encryptor -d <encrypted_file> <decrypted_output> <strong_password>
```

## Implementation
### Multithreading
The program performs chunked input reading, which works well on large files and keeps memory usage low and efficiency high.

It creates a number of *readers* threads that depends on the number of CPU processors currently online, in particular, it creates `cpu_active_cores - 1` *readers* threads reserving 1 core for the *writer* thread. 

Every *reader* thread does the following operations:
- reads the file chunk;
- performs chunk encryption/decryption;
- pushes the processed chunk inside the file chunks queue.

The *writer* extracts a file chunk from the queue and write it to the output file. 

### File processing
The file is split in chunks, as many as the *readers*. Each chunk is currently at most 16MB, but to check how any remainders (from division) bytes are managed, check the code or the example below.

If the file is too big, the file is at first split in portions and then split in chunks ensuring that the estimated maximum RAM required by the program will be: `(16MB * n_of_readers) + (16MB * queue_capacity) + other_small_quantities`.

This is an example you can find also in the code:
```c
 * 
 * Example with a 4-core CPU (3 readers, 1 writer) and a 100MB file:
 * +-----------------------------------------------------------------------------------------------------------+
 * |                                                    FILE (100MB Total)                                     |        
 * |  +----------------------------------------------------------+------------------------------------------+  |                         
 * |  |      Portion 1 (48MB + 4MB)                              |          Portion 2 (48MB)                |  |        
 * |  |  +---------------------+--------------+--------------+       +------------+----------+----------+   |  |                 
 * |  |  |   Chunk 1           |    Chunk 2   |   Chunk 3    |       |  Chunk 1   | Chunk 2  | Chunk 3  |   |  |
 * |  |  | (16MB + 1MB + 1MB)  | (16MB + 1MB) | (16MB + 1MB) |       |  (16MB)    | (16MB)   | (16MB)   |   |  |
 * |  |  +---------------------+--------------+--------------+       +------------+----------+----------+   |  |
 * |  +---------------------------------------------------+-------------------------------------------------+  |
 * +-----------------------------------------------------------------------------------------------------------+
 * chunksizeRem = 1MB; firstThreadRem = 1MB 
 * (16MB*3)*2) + (1MB*3) + 1MB = 100MB
 */
```

### Encryption/decryption
In order to encrypt/decrypt files, the program derives a `key` and a `nonce` from user's `password` and `salt` using PBKDF2.

Every file chunk encryption/decryption is totally isolated from others using OpenSSL's AES algorithm with CTR mode. For each chunk a new EVP context is initialized and an unique IV is generated using `nonce + chunk_index` (or counter), `nonce` and `key` are the same for all chunks. The *reader* thread encrypts/decrypts the chunk using the `key` and `iv` and frees the EVP context before moving on the next chunk. 


## Limitations
- Passwords cannot be verified yet so if the user enters a wrong password, it will simply get garbage output file and no errors will be shown. This feature should implement after encrypting, the computation of a cryptographic HMAC over the ciphertext and its comparing with a new one computed every time a password should be tested (over the same ciphertext).

## Tests
```sh
bash run_tests.sh
```