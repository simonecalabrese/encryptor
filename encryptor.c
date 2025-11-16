/*
 * 
 * Copyright (c) 2025, Simone Calabrese
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>

/* Maximum file chunk size processable by a Reader thread. */
#define MAX_READER_CHUNK_SIZE 1024*1024*16
/* Minimum file size to enable multithread execution. */
#define MIN_FILE_SIZE (1024*16) + 1
#define MIN_PASSWORD_LEN 8
#define QUEUE_CAPACITY 10
#define SALT_LEN 16 /* required to derive the key from a password. */
#define KEY_LEN 32 /* AES key fixed-length of 256 bit. */
#define NONCE_LEN 12 /* base nonce length. */
#define CHUNK_COUNTER_LEN 4 /* chunk counter (identifier) length. */
#define HEADER_OFFSET SALT_LEN+NONCE_LEN
/* More info at: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html */
#define PBKDF2_ITERATIONS 100000

#define exit_with_sys_err(err) {    \
    perror(err);                    \
    exit(EXIT_FAILURE);             \
}

#define exit_with_err(str, err) {                       \
    fprintf(stderr, "%s: %s\n", str, strerror(err));    \
    exit(EXIT_FAILURE);                                 \
}

#define exit_with_err_msg(str) {    \
    fprintf(stderr, "%s\n", str);   \
    exit(EXIT_FAILURE);             \
}

/* File chunk fetched by the writer thread and written to output file. */
typedef struct {
    /* size of the file chunk to write (varies between processed file portions). */
    uint32_t chunksize;
    uint64_t offset; /* offset of the current chunk */
    unsigned char *chunk;
} file_chunk;


/* ---------------------- Circular queue implementation -------------------- */

/* Fixed-capacity queue to store encrypted/decrypted file chunks.  */
typedef struct {
    file_chunk **data;
    int32_t in;
    int32_t out;
    int32_t size;
    int32_t capacity;
} queue_t;

void queue_init(queue_t *q, int32_t capacity) {
    if(!q || capacity == 0) exit_with_err_msg("queue_init");

    if((q->data = malloc(sizeof(file_chunk *) * capacity)) == NULL) 
        exit_with_sys_err("malloc queue");
    q->size = q->in = q->out = 0;
    q->capacity = capacity;
}

void queue_push(queue_t *q, uint32_t chunksize, uint64_t offset, unsigned char *chunk) {
    if(!q || !chunk || q->size >= q->capacity)
        exit_with_err_msg("queue_push");
    
    if((q->data[q->in] = malloc(sizeof(file_chunk))) == NULL)
        exit_with_sys_err("malloc queue push");
    if((q->data[q->in]->chunk = malloc(sizeof(unsigned char) * chunksize)) == NULL)
        exit_with_sys_err("malloc queue node attr");    
    memcpy(q->data[q->in]->chunk, chunk, chunksize);
    q->data[q->in]->chunksize = chunksize;
    q->data[q->in]->offset = offset;

    q->in = (q->in + 1) % q->capacity;
    q->size++;
}

file_chunk *queue_pop(queue_t *q) {
    if(!q || q->size <= 0 || q->capacity == 0)
        exit_with_err_msg("queue_pop");

    file_chunk *src = q->data[q->out];
    file_chunk *fc = malloc(sizeof(file_chunk));
    if (!fc)
        exit_with_sys_err("malloc queue pop");

    fc->chunksize = src->chunksize;
    fc->offset = src->offset;
    fc->chunk = malloc(fc->chunksize*sizeof(unsigned char));
    if (!fc->chunk)
        exit_with_sys_err("malloc queue chunk");
    memcpy(fc->chunk, src->chunk, fc->chunksize);

    free(src->chunk);
    free(src);
    q->data[q->out] = NULL;
    
    q->out = (q->out + 1) % q->capacity;
    q->size--;
    return fc;
}

void queue_destroy(queue_t *q) {
    if(!q || q->capacity == 0) exit_with_err_msg("queue_destroy");
    if(q->size == 0) return;
    for(int32_t i = 0; i < q->size; i++) {
        if(q->data[i] != NULL) {
            free(q->data[i]->chunk);
            free(q->data[i]);
            q->data[i] = NULL;
        }
    }
    free(q->data);
}

/* ------------------------------------------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t full;
    pthread_cond_t empty;
    queue_t *q; /* queue to store processed file chunks to write. */
    uint16_t readers_n; /* total reader threads (or chunks in each portion). */
    uint16_t readers_exited; /* reader threads terminated */
    bool dflag; /* decryption flag */
} shared_data;

typedef struct {
    pthread_t tid;
    uint16_t id;
    uint16_t portions_n;
    uint32_t chunksize;
    uint32_t chunksizeRem; /* remaining bytes from division among reader(s)  */
    uint32_t firstThreadRem; /* remaining bytes read only by the first reader */
    char *filepath;
    const unsigned char *key; /* derived key from password */
    const unsigned char *nonce;
    // shared
    shared_data *s;   
} reader_data;

typedef struct {
    pthread_t tid;
    char *filepath;
    off_t filesize;
    // shared
    shared_data *s;
} writer_data;

void mutex_lock(pthread_mutex_t *mutex) {
    int err;
    if((err = pthread_mutex_lock(mutex)) != 0)
        exit_with_err("pthread_mutex_lock", err);
}

void mutex_unlock(pthread_mutex_t *mutex) {
    int err;
    if((err = pthread_mutex_unlock(mutex)) != 0)
        exit_with_err("pthread_mutex_unlock", err);
}

void cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    int err;
    if((err = pthread_cond_wait(cond, mutex)) != 0)
        exit_with_err("pthread_cond_wait", err);
}

void cond_broadcast(pthread_cond_t *cond) {
    int err;
    if((err = pthread_cond_broadcast(cond)) != 0)
        exit_with_err("pthread_cond_broadcast", err);
}

void cond_signal(pthread_cond_t *cond) {
    int err;
    if((err = pthread_cond_signal(cond)) != 0)
        exit_with_err("pthread_cond_signal", err);
}

/* Derive a `key` and a `nonce` for cryptographic operations from user `password` and `salt` using PBKDF2.
 * NOTE: The salt parameter must be previously randomly generated or should be the previously
 * value used to encrypt the file which now must be decrypted; the nonce must be managed like
 * the salt except that it is automatically generated if a previous value is not passed. */
void derive_key_nonce(const char *passw, unsigned char *salt, unsigned char *key, unsigned char *nonce) {
    unsigned char key_nonce[KEY_LEN + NONCE_LEN];

    if (!PKCS5_PBKDF2_HMAC(passw, strlen(passw), salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(), sizeof(key_nonce), key_nonce))
        exit_with_err_msg("PBKDF2 failed");

    memcpy(key, key_nonce, KEY_LEN);
    memcpy(nonce, key_nonce + KEY_LEN, NONCE_LEN);
}

/* Convert passed uint32 `val` to uint8[4] Big Endian `out`. */
void uint32_to_bytes_be(uint32_t val, uint8_t out[4]) {
    out[0] = (val >> 24) & 0xFF;
    out[1] = (val >> 16) & 0xFF;
    out[2] = (val >> 8)  & 0xFF;
    out[3] = val & 0xFF;
}

/* Encrypt a file chunk using a unique IV composed by nonce + chunk_unique_index. */
int encrypt_chunk(unsigned char *out, const unsigned char *in, const int inlen, const unsigned char *key, const unsigned char *nonce, const uint32_t chunk_index) {
    /* Build iv from nonce + chunk_index. */
    unsigned char iv[NONCE_LEN+CHUNK_COUNTER_LEN];
    memcpy(iv, nonce, NONCE_LEN);
    uint8_t chunk_i_be[4];
    uint32_to_bytes_be(chunk_index, chunk_i_be);
    memcpy(iv+NONCE_LEN, &chunk_i_be, sizeof(chunk_i_be));
    // aes_256_ctr_encrypt_chunk(key, nonce, chunk_index, in, out, inlen);
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) exit_with_err_msg("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
        exit_with_err_msg("EVP_EncryptInit_ex failed");
    
    if (EVP_EncryptUpdate(ctx, out, &outlen, in, inlen) != 1)
        exit_with_err_msg("EVP_EncryptUpdate failed");

    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

/* Decrypt a file chunk using the corresponding chunk IV composed by nonce + chunk_unique_index. */
int decrypt_chunk(unsigned char *outbuf, const unsigned char *inbuf, const int inlen, const unsigned char *key, const unsigned char *nonce, const uint32_t chunk_index) {
    /* Build iv from nonce + chunk_index. */
    unsigned char iv[NONCE_LEN+CHUNK_COUNTER_LEN];
    memcpy(iv, nonce, NONCE_LEN);
    uint8_t chunk_i_be[4];
    uint32_to_bytes_be(chunk_index, chunk_i_be);
    memcpy(iv+NONCE_LEN, &chunk_i_be, sizeof(chunk_i_be));
    // aes_256_ctr_decrypt_chunk(key, nonce, chunk_index, inbuf, outbuf, inlen);
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) exit_with_err_msg("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
        exit_with_err_msg("EVP_DecryptInit_ex failed");
    
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1)
        exit_with_err_msg("EVP_DecryptUpdate failed");

    EVP_CIPHER_CTX_free(ctx);

    return outlen;
}

/* Reader thread function.
 * Each reader thread reads a file chunk at time for every portion the file has been split.
 * A file chunk contains `chunksize` bytes and only in the first file portion a reader might also
 * read `chunksizeRem` bytes as reminder after total file size division among all the others.
 * Only the first reader thread might also read extra `firstThreadRem` bytes.
 * These two bytes reminders are required in order to process the input file dividing it in portions,
 * each one split in chunks (as many as the number of readers).
 * This approach helps avoid the need to load the entire file into memory at once, making it 
 * possible to process large files (e.g., an 1GB file) without requiring 1GB of free RAM.
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
void *reader_fn(void *arg) {
    reader_data *data = (reader_data *)arg;
    int fd;
    if((fd = open(data->filepath, O_RDONLY)) == -1)
        exit_with_sys_err("reader open file");
    /* Start to read file portions: reader thread with id 0 reads the first chunk
     * for every file portion, reader with id 1 (if exists) reads the second chunk
     * inside each portion and so on. */
    uint16_t portions_n = data->portions_n;
    /* First reader must read extra bytes (reminder) so it needs to process
     * an extra file portion. */
    if(data->id == 0) portions_n++;
    for(uint16_t i = 0; i < portions_n; i++) {
        unsigned char *c; /* chunk to encrypt/decrypt */
        uint32_t csize; /* chunk size*/
        if(i == 0)
            csize = data->chunksize+data->chunksizeRem;
        else
            csize = data->chunksize;
        
        if((c = malloc(sizeof(unsigned char)*csize)) == NULL)
            exit_with_sys_err("reader chunk malloc");
        
        uint64_t portionStart = (((uint64_t)(csize*data->s->readers_n))*i);
        if(i > 0) portionStart += (data->chunksizeRem*data->s->readers_n);
        uint64_t offset = (portionStart + (csize*data->id));

        if(data->id == 0 && i == portions_n-1) {
            /* Start of last portion where the remaining bytes must be written. */
            offset = (((uint64_t)(data->chunksize*data->s->readers_n))*data->portions_n)+(data->chunksizeRem*data->s->readers_n);
            csize = data->firstThreadRem;
        }
            

        if(data->s->dflag == true) {
            /* Add input (cipher) header offset before reading encrypted file chunk. */
            offset += HEADER_OFFSET;
        }
        
        if(lseek(fd, offset, SEEK_SET) == -1)
            exit_with_sys_err("reader lseek");

        /* Read chunk from file. */
        if(read(fd, c, csize) == -1)
            exit_with_sys_err("reader read");
        
        /* Add or remove file header offset for cryptographic operations before writing decrypted file chunk. */
        if(data->s->dflag == true)
            offset -= HEADER_OFFSET;
        else
            offset += HEADER_OFFSET;

        /* Buffer for encryption/decryption result. */
        unsigned char *buf;
        if((buf = malloc(sizeof(unsigned char)*(csize+EVP_MAX_BLOCK_LENGTH))) == NULL)
            exit_with_sys_err("reader buf malloc");
        int bytes = 0; /* bytes encrypted/decrypted. */

        if(data->s->dflag == false)
            bytes = encrypt_chunk(buf, c, (int)csize, data->key, data->nonce, (data->id+(i*data->s->readers_n)));
        else
            bytes = decrypt_chunk(buf, c, (int)csize, data->key, data->nonce, (data->id+(i*data->s->readers_n)));
        free(c);

        mutex_lock(&data->s->mutex);

        /* File chunks queue is full: wait for writer. */
        while(data->s->q->size == data->s->q->capacity)
            cond_wait(&data->s->empty, &data->s->mutex);
        /* Push processed file chunk into queue. */

        queue_push(data->s->q, bytes, offset, buf);
        /* Wake writer. */
        cond_signal(&data->s->full);
        mutex_unlock(&data->s->mutex);

        free(buf);
    }
    
    mutex_lock(&data->s->mutex);
    
    data->s->readers_exited++;

    if(data->s->readers_exited == data->s->readers_n) {
        /* Wake writer. End of work. */
        cond_signal(&data->s->full);
    }

    mutex_unlock(&data->s->mutex);

    close(fd);
    pthread_exit(NULL);
}

/* Writer thread function. */
void *writer_fn(void *arg) {
    writer_data *data = (writer_data *)arg;
    int fd;
    if(data->s->dflag == false)
        fd = open(data->filepath, O_WRONLY);
    else
        fd = open(data->filepath, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if(fd == -1)
        exit_with_sys_err("writer open file");
    uint64_t sum = 0;
    bool end = false;
    while(1) {
        mutex_lock(&data->s->mutex);

        while(data->s->q->size == 0 && data->s->readers_exited < data->s->readers_n)
            cond_wait(&data->s->full, &data->s->mutex);

        if(data->s->q->size == 0 && data->s->readers_exited == data->s->readers_n) {
            mutex_unlock(&data->s->mutex);
            break;
        }
        
        if(data->s->q->size > 0) {
            file_chunk *fc = queue_pop(data->s->q);

            /* Wake readers */
            cond_broadcast(&data->s->empty);

            /* All readers exited. End of work. */
            if(data->s->q->size == 0 && data->s->readers_exited == data->s->readers_n) {
                end = true;
            }

            mutex_unlock(&data->s->mutex);

            if(lseek(fd, fc->offset, SEEK_SET) == -1)
                exit_with_sys_err("writer lseek");
            if(fc->chunksize > 0) {
                if(write(fd, fc->chunk, fc->chunksize) == -1)
                    exit_with_sys_err("writer chunk");
                sum += fc->chunksize;
            }

            free(fc->chunk);
            free(fc);

            /* Print loading percentage */
            if(data->filesize > 0) {
                printf("\r%s... %d%%",(data->s->dflag) ? "Decrypting" : "Encrypting", (int)((sum*100)/data->filesize));
                fflush(stdout); // Flush the output buffer
            }
        }
        
        if(end) break;    
    }
    close(fd);
    pthread_exit(NULL);
}

/* Format bytes into a human-readable string of length `n` (e.g. "1.00 MB" or "1.20 GB") */
void bytes_format(long double bytes, char *out, int n) {
    const char *units[] = {"bytes", "KB", "MB", "GB"};
    int i = 0;
    while (bytes >= 1024 && i < 3) {
        bytes /= 1024;
        i++;
    }
    snprintf(out, n, "%.2Lf %s", bytes, units[i]);
}

int main(int argc, char *argv[]) {
    int err;
    /* Start measuring execution time. */
    time_t start = time(NULL);

    bool dflag = false; // Decrypt flag
    if(argc > 1 && strcmp(argv[1], "-d") == 0) {
        dflag = true;
    }

    /* Validate argv. */
    bool args_err = false;
    if(dflag) {
        if(argc < 5)
            args_err = true;
    } else {
        if(argc < 4)
            args_err = true;
    }
    if(args_err)
        exit_with_err_msg("run syntax error\ncorrect usage: file-encryptor [-d] <file-input> <file-output> <strong_password> \n");

    uint8_t input_file_i = 1;
    if(dflag) input_file_i++; 

    /* Validate password. */
    if(strlen(argv[input_file_i+2]) < MIN_PASSWORD_LEN) {
        fprintf(stderr, "password must be at least %d characters\n", MIN_PASSWORD_LEN);
        exit(EXIT_FAILURE);
    }

    struct stat inputf; /* Input file stat */
    if((stat(argv[input_file_i], &inputf) == -1))
        exit_with_sys_err("stat");
    if (inputf.st_size < 0)
        exit_with_err_msg("invalid filesize value");

    uint64_t ifsize = (uint64_t)inputf.st_size;

    /* Prepare required input data for encryption/decryption. */
    unsigned char *salt = malloc(sizeof(unsigned char) * SALT_LEN);
    unsigned char *key = malloc(sizeof(unsigned char) * KEY_LEN);
    unsigned char *nonce = malloc(sizeof(unsigned char) * NONCE_LEN);
    if(!salt || !key || !nonce)
        exit_with_err_msg("malloc");

    if(dflag == true) {
        /* Read salt and nonce from input cipher file header in order to derive the key. */
        int inputf = open(argv[input_file_i], O_RDONLY);
        if (inputf < 0)
            exit_with_sys_err("open input file");
        if (read(inputf, salt, SALT_LEN) != SALT_LEN || read(inputf, nonce, NONCE_LEN) != NONCE_LEN)
            exit_with_sys_err("cannot read input file header");
        close(inputf);
        /* Ignore header length from total file size before chunk split. */
        ifsize -= HEADER_OFFSET;
    }
    else {
        /* Generate random salt for deriving the key. */
        if (!RAND_bytes(salt, SALT_LEN))
            exit_with_sys_err("RAND_bytes (salt)");
    }

    /* Derive AES key from input password. */
    derive_key_nonce(argv[input_file_i+2], salt, key, nonce);
    if(dflag == false) {
        /* Write salt and nonce to output cipher file header for future decryption. */
        int outputf = open(argv[input_file_i+1], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
        if (outputf < 0)
            exit_with_sys_err("open output file");
        /* Write salt and nonce at the beginning of output file. */
        if (write(outputf, salt, SALT_LEN) != SALT_LEN || write(outputf, nonce, NONCE_LEN) != NONCE_LEN)
            exit_with_sys_err("write outputf header");
        close(outputf);
    }

    /* Fetch current number of CPU processors currently online */
    long cpu_cores_n = sysconf(_SC_NPROCESSORS_ONLN);
    if(cpu_cores_n == -1) 
        exit_with_sys_err("sysconf");
    /* Set number of cores from args for testing. */
    if((strstr(argv[argc-1], "CPU_CORES=")) != NULL) {
        char test_cores_n[8];
        strncpy(test_cores_n, strchr(argv[argc-1], '=')+1, 7);
        test_cores_n[7] = 0;
        int n = atoi(test_cores_n);
        cpu_cores_n = n;
    }
    if(cpu_cores_n <= 1)
        cpu_cores_n = 1;
    /* The number of reader threads will be cpu_cores_n - 1 (or 1) so that
    * 1 processor can be used by the only writer thread. */
    uint16_t readers_n = (cpu_cores_n > 1) ? cpu_cores_n - 1 : 1;

    /* Fetch current available free memory */
    struct sysinfo sys;
    if (sysinfo(&sys) == -1) {
        exit_with_sys_err("sysinfo");
    }
    uint32_t req_mem = MIN_FILE_SIZE; /* free memory required to run */
    /* Consider 80% of the free memory to prevent filling it excessively. */
    uint32_t free_mem = (uint32_t)(sys.freeram*0.8);
    /* Size of the biggest file portion processable without losing efficiency. */
    const uint32_t portion_max_size = (readers_n*MAX_READER_CHUNK_SIZE); 
    /* Total portions to split file into.  */
    uint16_t portions_n = 1;
    /* Bytes to read inside from the current portion of the file */
    uint32_t chunksize = 0;
    /* Remaining bytes to read only within 1 portion of the file (the first one) */
    uint32_t chunksizeRem = 0;
    /* Any remaining bytes after bytes distribution among threads that must be
     * read only once by the FIRST thread. */
    uint32_t firstThreadRem = 0;

    /* Run using a single thread. */
    if(ifsize < MIN_FILE_SIZE) {
        readers_n = 1;
        req_mem = ifsize;
        chunksize = ifsize;
    } 
    /* All the `readers_n` threads will process the input file. */
    else {
        /* File is made up by only 1 portion. */
        if(ifsize <= portion_max_size) {
            chunksize = (ifsize / readers_n);
            /* Add any remaining bytes to read to the first reader thread. */
            if(ifsize % readers_n > 0) {
                firstThreadRem = (ifsize % readers_n);
            }
            req_mem = ifsize;
        }
        /* File is made up by more than 1 portion. */
        else {
            req_mem = portion_max_size;

            portions_n = (uint16_t)(ifsize / portion_max_size);
            chunksize = MAX_READER_CHUNK_SIZE;
            /* Add any extra bytes caused by divisions remainders: first reader thread might read
             * a bigger chunk than others (if there are any divisions reminders) */
            uint32_t rem = ifsize % portion_max_size;
            if(rem > 0) {
                if(rem < MIN_FILE_SIZE) {
                    firstThreadRem = rem;
                } else {
                    /* Process the extra portion for the remaining bytes */
                    chunksizeRem = rem / readers_n;
                    /* Add any remaining bytes to the first reader thread. */
                    if(rem % readers_n > 0) {
                        /* These bytes must be read at the end and offset last_portion_index+1. */
                        firstThreadRem = rem % readers_n;
                    }
                }
            }
        }
    }
    
    /* Consider also file chunks inside queue. */
    req_mem += (QUEUE_CAPACITY*MAX_READER_CHUNK_SIZE);

    if(free_mem < req_mem)
        exit_with_err_msg("Insufficient free memory. Close some applications and try again."); 

    char hfsize[12];
    bytes_format(ifsize, hfsize, 12);
    printf("File: %s (%s)... \n", argv[input_file_i], hfsize);
    printf("Using %ld CPU cores\n", cpu_cores_n);
    // printf("Starting %u threads; %u readers, %u writer\n", readers_n+1, readers_n, 1);

    /* Prepare queue for file chunks to process. */
    queue_t q;
    queue_init(&q, QUEUE_CAPACITY);

    /* Prepare shared data among threads. */
    shared_data shared;
    shared.dflag = dflag;
    shared.readers_exited = 0;
    shared.readers_n = readers_n;
    shared.q = &q;
    if((err = pthread_mutex_init(&shared.mutex, NULL)) != 0)
        exit_with_err("pthread_mutex_init", err);
    if((err = pthread_cond_init(&shared.full, NULL)) != 0)
        exit_with_err("pthread_cond_init", err);
    if((err = pthread_cond_init(&shared.empty, NULL)) != 0)
        exit_with_err("pthread_cond_init", err);

    /* Prepare readers threads data */
    reader_data readers[readers_n];
    for(uint16_t i = 0; i < readers_n; i++) {
        readers[i].id = i;
        if((readers[i].filepath = malloc(sizeof(char)*(strlen(argv[input_file_i])+1))) == NULL)
            exit_with_sys_err("filepath malloc");
        strcpy(readers[i].filepath, argv[input_file_i]);
        readers[i].portions_n = portions_n;
        readers[i].chunksize = chunksize;
        readers[i].chunksizeRem = chunksizeRem;
        readers[i].firstThreadRem = firstThreadRem;
        readers[i].key = key;
        readers[i].nonce = nonce;
        readers[i].s = &shared;
    }
    
    uint64_t total_bytes_to_process = (((uint64_t)(chunksize*readers_n))*portions_n)+(chunksizeRem*readers_n)+firstThreadRem;
    if(ifsize != total_bytes_to_process) {
        printf("error\nTotal input file bytes (%ld) mismatch after initial chunk processing %lu\n", ifsize, total_bytes_to_process);
        exit(EXIT_FAILURE);
    }

    /* Prepare writer thread data. */
    writer_data writer;
    writer.filesize = ifsize;
    if((writer.filepath = malloc(sizeof(char)*(strlen(argv[input_file_i+1])+1))) == NULL)
        exit_with_sys_err("writer filepath malloc");
    strcpy(writer.filepath, argv[input_file_i+1]);
    writer.s = &shared;

    /* Create threads. */
    if((err = pthread_create(&writer.tid, NULL, writer_fn, &writer)) != 0)
        exit_with_err("pthread_create", err);
    for(uint16_t i = 0; i < readers_n; i++) {
        if((err = pthread_create(&readers[i].tid, NULL, reader_fn, &readers[i])) != 0)
            exit_with_err("pthread_create", err);
    }

    /* Wait for threads termination. */
    if((err = pthread_join(writer.tid, NULL)) != 0)
        exit_with_err("pthread_join", err);
    for(uint16_t i = 0; i < readers_n; i++) {
        if((err = pthread_join(readers[i].tid, NULL)) != 0)
            exit_with_err("pthread_join", err);
    }

    /* Destroy objects */
    if((err = pthread_mutex_destroy(&shared.mutex)) != 0)
        exit_with_err("pthread_mutex_destroy", err);
    if((err = pthread_cond_destroy(&shared.full)) != 0)
        exit_with_err("pthread_cond_destroy", err);
    if((err = pthread_cond_destroy(&shared.empty)) != 0)
        exit_with_err("pthread_cond_destroy", err);

    /* Free allocated memory */
    free(writer.filepath);
    for(uint16_t i = 0; i < readers_n; i++) {
        free(readers[i].filepath);
    }
    queue_destroy(&q);
    free(salt);
    free(key);
    free(nonce);
    
    /* Total execution time in seconds. */
    long secs = (long)(time(NULL) - start);
    printf("\nFile %s in %ld seconds!\n", (dflag) ? "decrypted" : "encrypted", secs);
    
    exit(EXIT_SUCCESS);
}