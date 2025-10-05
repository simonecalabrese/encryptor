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
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>

/* Maximum file chunk size processable by . */
#define MAX_READER_CHUNK_SIZE 1024*1024*16
/* Minimum file size to enable multithread execution. */
#define MIN_FILE_SIZE (1024*16) + 1

#define SALT_LEN 16 /* required to derive the key from a password. */
#define KEY_LEN 32 /* AES key fixed-length of 256 bit. */
#define IV_LEN 16 /* inizialization vector length. */
#define HEADER_OFFSET SALT_LEN+IV_LEN
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

/* This struct contains all the shared informations that must be filled in
* every time a reader finishes to encrypt a (file) portion chunk.
* Only one file chunk at a time will be stored inside this structure and 
* written to the output file by the writer thread.  */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t write;
    pthread_cond_t *readers;
    /* size of the file chunk to write (varies between processed file portions). */
    size_t chunksize;
    size_t offset; /* offset of the current chunk */
    unsigned char *chunk;
    unsigned char *key;
    unsigned char *iv;
    unsigned int turn; /* reader thread index inside array */
    unsigned int readers_n; /* total reader threads */
    unsigned int readers_exited; /* reader threads terminated */
    bool written; /* writer work flag */
    bool fetched; /* reader work flag */
    bool dflag; /* decryption flag */
    EVP_CIPHER_CTX *ctx;
} shared_data;

typedef struct {
    pthread_t tid;
    unsigned int id;
    unsigned long portions_n;
    size_t chunksize;
    size_t chunksizeRem; /* remaining bytes from division among reader(s)  */
    size_t firstThreadRem; /* remaining bytes read only by the first reader */
    char *filepath;
    // shared with writer
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

/* Derive `key` and `IV` from `password` using PBKDF2 and a previously randomly generated
 * `salt` or the previously used salt to encrypt the file that now must be decrypted. */
void derive_key_iv(const char *passw, unsigned char *salt, unsigned char *key, unsigned char *iv) {
    unsigned char key_iv[KEY_LEN + IV_LEN];

    if (!PKCS5_PBKDF2_HMAC(passw, strlen(passw), salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(), sizeof(key_iv), key_iv)) {
        fprintf(stderr, "PBKDF2 failed\n");
        exit(EXIT_FAILURE);
    }

    memcpy(key, key_iv, KEY_LEN);
    memcpy(iv, key_iv + KEY_LEN, IV_LEN);
}

/* Reader thread function. */
void *reader_fn(void *arg) {
    reader_data *data = (reader_data *)arg;
    int fd;
    if((fd = open(data->filepath, O_RDONLY)) == -1)
        exit_with_sys_err("reader open file");
    /* Start to read file portions: reader thread with id 0 reads the first chunk
     * for every file portion, reader with id 1 (if exists) reads the second chunk
     * inside each portion and so on. */
    for(unsigned int i = 0; i < data->portions_n; i++) {
        unsigned char *c; /* chunk to encrypt/decrypt */
        size_t csize; /* chunk size*/
        if(i == 0)
            csize = data->chunksize+data->chunksizeRem;
        else
            csize = data->chunksize;
        
        if((c = malloc(sizeof(unsigned char)*csize)) == NULL)
            exit_with_sys_err("reader chunk malloc");
        
        size_t portionStartIndex = (csize*data->s->readers_n*i);
        if(i > 0) portionStartIndex += (data->chunksizeRem*data->s->readers_n);
        size_t offset = (portionStartIndex + (csize*data->id));

        if(data->s->dflag == true) {
            /* Add input (cipher) header offset before reading encrypted file chunk. */
            offset += HEADER_OFFSET;
        }
        
        if(lseek(fd, offset, SEEK_SET) == -1)
            exit_with_sys_err("reader lseek");

        /* Read chunk from file. */
        if(read(fd, c, csize) == -1)
            exit_with_sys_err("reader read");

        /* Buffer for encryption/decryption result. */
        unsigned char *buf;
        if((buf = malloc(sizeof(unsigned char)*(csize+EVP_MAX_BLOCK_LENGTH))) == NULL)
            exit_with_sys_err("reader buf malloc");
        int bytes = 0; /* bytes encrypted/decrypted. */

        mutex_lock(&data->s->mutex);

        /* Wait for its turn to send chunk to writer. */
        while(data->s->turn != data->id)
            cond_wait(&data->s->readers[data->id], &data->s->mutex);

        if(data->s->dflag == false) {
            if (EVP_EncryptUpdate(data->s->ctx, buf, &bytes, c, (int)csize) != 1) {
                fprintf(stderr, "EVP_EncryptUpdate failed\n");
                EVP_CIPHER_CTX_free(data->s->ctx);
                exit(EXIT_FAILURE);
            }
        } else {
            if (EVP_DecryptUpdate(data->s->ctx, buf, &bytes, c, (int)csize) != 1) {
                fprintf(stderr, "EVP_DecryptUpdate failed\n");
                EVP_CIPHER_CTX_free(data->s->ctx);
                exit(EXIT_FAILURE);
            }
        }
        if(bytes == 0) exit_with_sys_err("BYTES0");

        free(c);
        
        if((data->s->chunk = realloc(data->s->chunk, sizeof(unsigned char)*bytes)) == NULL)
            exit_with_sys_err("reader realloc shared chunk");
        memcpy(data->s->chunk, buf, bytes);
        free(buf);
        data->s->chunksize = bytes;
        if(data->s->dflag == true) {
            /* Remove input (cipher) header offset before writing decrypted file chunk. */
            offset -= HEADER_OFFSET;
        } else {
            /* Add input (cipher) header offset before writing encrypted file chunk. */
            offset += HEADER_OFFSET;
        }
        data->s->offset = offset;
        data->s->fetched = true;
        /* Wake writer */
        cond_signal(&data->s->write);
        /* Wait for writer */
        while(!data->s->written)
            cond_wait(&data->s->write, &data->s->mutex);
        data->s->written = false;
        data->s->turn = (data->s->turn+1)%data->s->readers_n;

        /* Wake readers */
        cond_signal(&data->s->readers[data->s->turn]);

        mutex_unlock(&data->s->mutex);
    }
    
    mutex_lock(&data->s->mutex);

    /* First reader must read extra bytes (reminder) after all the other readers exited. */
    if(data->id == 0 && data->firstThreadRem > 0) {
        while(data->s->readers_exited < data->s->readers_n-1)
            cond_wait(&data->s->readers[0], &data->s->mutex);

        data->s->readers_exited++;
        data->s->turn = data->s->readers_n-1;
        /* Start of last portion where the remaining bytes must be written. */
        size_t offset = (data->chunksize*data->s->readers_n*data->portions_n)+(data->chunksizeRem*data->s->readers_n);
        if(data->s->dflag == true)
            offset += HEADER_OFFSET;

        if(lseek(fd, offset, SEEK_SET) == -1)
            exit_with_sys_err("reader final lseek");

        if((data->s->chunk = realloc(data->s->chunk, sizeof(unsigned char)*data->firstThreadRem)) == NULL)
            exit_with_sys_err("reader realloc shared chunk");

        /* Read chunk from file. */
        if(read(fd, data->s->chunk, data->firstThreadRem) == -1)
            exit_with_sys_err("reader read");

        unsigned char *buf;
        if((buf = malloc(sizeof(unsigned char)*(data->firstThreadRem+EVP_MAX_BLOCK_LENGTH))) == NULL)
            exit_with_sys_err("reader buf malloc");
        int bytes = 0; /* bytes encrypted/decrypted. */
    
        if(data->s->dflag == false) {
            if (EVP_EncryptUpdate(data->s->ctx, buf, &bytes, data->s->chunk, (int)data->firstThreadRem) != 1) {
                fprintf(stderr, "EVP_EncryptUpdate failed\n");
                EVP_CIPHER_CTX_free(data->s->ctx);
                exit(EXIT_FAILURE);
            }
        } else {
            if (EVP_DecryptUpdate(data->s->ctx, buf, &bytes, data->s->chunk, (int)data->firstThreadRem) != 1) {
                fprintf(stderr, "EVP_DecryptUpdate failed\n");
                EVP_CIPHER_CTX_free(data->s->ctx);
                exit(EXIT_FAILURE);
            }
        }

        memcpy(data->s->chunk, buf, bytes);
        free(buf);
        data->s->chunksize = bytes;
        if(data->s->dflag == true) {
            /* Remove input (cipher) header offset before writing decrypted file chunk. */
            offset -= HEADER_OFFSET;
        } else {
            /* Add input (cipher) header offset before writing encrypted file chunk. */
            offset += HEADER_OFFSET;
        }
        data->s->offset = offset;
        data->s->fetched = true;
    } 
    else {
        data->s->chunksize = 0;
        data->s->readers_exited++;
        cond_signal(&data->s->readers[0]);
    }
    
    if(data->s->readers_exited == data->s->readers_n) {
        /* Wake writer. End of work. */
        cond_signal(&data->s->write);
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
    mutex_lock(&data->s->mutex);
    size_t sum = 0;
    while(1) {
        while(data->s->fetched == false && data->s->readers_exited < data->s->readers_n)
            cond_wait(&data->s->write, &data->s->mutex);

        if(lseek(fd, data->s->offset, SEEK_SET) == -1)
            exit_with_sys_err("writer lseek");
        if(data->s->chunksize > 0) {
            if(write(fd, data->s->chunk, data->s->chunksize) == -1)
                exit_with_sys_err("writer chunk");
            printf("WRITER %ld bytes written\n", data->s->chunksize);
            sum += data->s->chunksize;
        }
        /* All readers exited. End of work. */
        if(data->s->readers_exited == data->s->readers_n) {
            printf("WRITER total %ld bytes written\n", sum);
            EVP_CIPHER_CTX_free(data->s->ctx);
            break;
        }
        data->s->written = true;
        data->s->fetched = false;
        /* Wake reader */
        cond_signal(&data->s->write);

        // Print loading percentage
        if(data->filesize > 0) {
            // printf("\rEncrypting... %d%%", (int)((sum*100)/data->filesize));
            // fflush(stdout); // Flush the output buffer
        }
    }
    mutex_unlock(&data->s->mutex);
    close(fd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if(argc < 4) {
        printf("run syntax error\n"
        "correct usage: file-encryptor [-d] <file-input> <file-output> <strong_password> \n");
        exit(EXIT_FAILURE);
    }
    int err;
    /* Start measuring execution time. */
    time_t start = time(NULL);

    bool dflag = false; // Decrypt flag
    if(strcmp(argv[1], "-d") == 0) {
        dflag = true;
    }

    int input_file_i = 1;
    if(dflag) input_file_i++; 

    struct stat inputf; /* Input file stat */
    if((stat(argv[input_file_i], &inputf) == -1))
        exit_with_sys_err("stat");
    off_t ifsize = inputf.st_size;

    /* Prepare required input data for encryption/decryption. */
    unsigned char *salt = malloc(sizeof(unsigned char) * SALT_LEN);
    unsigned char *key = malloc(sizeof(unsigned char) * KEY_LEN);
    unsigned char *iv = malloc(sizeof(unsigned char) * IV_LEN);
    if(!salt || !key || !iv)
        exit_with_err_msg("malloc");

    if(dflag == true) {
        /* Read salt and IV from input cipher file header in order to derive the key. */
        int inputf = open(argv[input_file_i], O_RDONLY);
        if (inputf < 0)
            exit_with_sys_err("open input file");
        if (read(inputf, salt, SALT_LEN) != SALT_LEN || read(inputf, iv, IV_LEN) != IV_LEN)
            exit_with_sys_err("cannot read input file header");
        close(inputf);
        printf("SALT: %s\nIV: %s\n", salt, iv);
        /* Ignore header length from total file size before chunk split. */
        ifsize -= HEADER_OFFSET;
    }
    else {
        /* Generate random salt for deriving the key. */
        if (!RAND_bytes(salt, SALT_LEN))
            exit_with_sys_err("RAND_bytes (salt)");
        printf("Generated SALT: %s\n", salt);
    }

    /* Derive AES key from input password. */
    printf("Password: %s\n", argv[input_file_i+2]);
    derive_key_iv(argv[input_file_i+2], salt, key, iv);
    printf("Derived key from passw: %s\n", key);
    if(dflag == false) {
        /* Write salt and IV to output cipher file header for future decryption. */
        int outputf = open(argv[input_file_i+1], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
        if (outputf < 0)
            exit_with_sys_err("open output file");
        /* Write salt and IV at the beginning of output file. */
        if (write(outputf, salt, SALT_LEN) != SALT_LEN || write(outputf, iv, IV_LEN) != IV_LEN)
            exit_with_sys_err("write outputf header");
        close(outputf);
    }

    /* Fetch current number of CPU processors currently online */
    long cpu_cores_n = sysconf(_SC_NPROCESSORS_ONLN);
    if(cpu_cores_n == -1) 
        exit_with_sys_err("sysconf");
    if(cpu_cores_n <= 1)
        cpu_cores_n = 1;
    /* The number of reader threads will be cpu_cores_n - 1 (or 1) so that
    * 1 processor can be used by the only writer thread. */
    unsigned int readers_n = (cpu_cores_n > 1) ? cpu_cores_n - 1 : 1;

    /* Fetch current available free memory */
    struct sysinfo sys;
    if (sysinfo(&sys) == -1) {
        exit_with_sys_err("sysinfo");
    }
    unsigned long req_mem = MIN_FILE_SIZE; /* free memory required to run */
    /* Consider 80% of the free memory to prevent filling it excessively. */
    unsigned long free_mem = (unsigned long)(sys.freeram*0.8);
    /* Size of the biggest file portion processable without losing efficiency. */
    const unsigned long portion_max_size = (readers_n*MAX_READER_CHUNK_SIZE); 
    /* Total portions to split file into.  */
    unsigned int portions_n = 1;
    /* Bytes to read inside from the current portion of the file */
    size_t chunksize = 0;
    /* Remaining bytes to read only within 1 portion of the file (the first one) */
    size_t chunksizeRem = 0;
    /* Any remaining bytes after bytes distribution among threads that must be
     * read only once by the FIRST thread. */
    size_t firstThreadRem = 0;

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

            portions_n = (unsigned int)(ifsize / portion_max_size);
            chunksize = MAX_READER_CHUNK_SIZE;
            /* Add any extra bytes caused by divisions remainders: first reader thread might read
             * a bigger chunk than others (if there are any divisions reminders) */
            unsigned long rem = ifsize % portion_max_size;
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

    if(free_mem < req_mem) {
        printf("Insufficient free memory. Close some applications and try again.\n");
        exit(EXIT_FAILURE);
    }

    printf("File: %s (%lu bytes)... \n", argv[input_file_i], ifsize);
    printf("File split in %u portions\n", portions_n);
    printf("File Portion size %lu bytes \n", (ifsize > portion_max_size) ? portion_max_size: ifsize);
    printf("Using %ld CPU cores\n", cpu_cores_n);
    printf("Starting %u threads; %u readers, %u writer\n", readers_n+1, readers_n, 1);

    /* Initialize cipher context. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        exit_with_err_msg("EVP_CIPHER_CTX_new failed");
    if(dflag == false) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
            fprintf(stderr, "EVP_EncryptInit_ex failed\n");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    } else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
            fprintf(stderr, "EVP_DecryptInit_ex failed\n");
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }

    /* Prepare shared data among threads. */
    shared_data shared;
    shared.turn = 0;
    shared.written = false;
    shared.fetched = false;
    shared.dflag = dflag;
    shared.readers_exited = 0;
    shared.readers_n = readers_n;
    shared.chunk = NULL;
    shared.key = key;
    shared.iv = iv;
    shared.ctx = ctx;
    if((err = pthread_mutex_init(&shared.mutex, NULL)) != 0)
        exit_with_err("pthread_mutex_init", err);
    if((err = pthread_cond_init(&shared.write, NULL)) != 0)
        exit_with_err("pthread_cond_init", err);
    shared.readers = malloc(sizeof(pthread_cond_t) * readers_n);
    for(unsigned int i = 0; i < readers_n; i++)
        pthread_cond_init(&shared.readers[i], NULL);

    /* Prepare readers threads data */
    reader_data readers[readers_n];
    for(unsigned int i = 0; i < readers_n; i++) {
        readers[i].id = i;
        if((readers[i].filepath = malloc(sizeof(char)*strlen(argv[input_file_i]))) == NULL)
            exit_with_sys_err("filepath malloc");
        strcpy(readers[i].filepath, argv[input_file_i]);
        readers[i].portions_n = portions_n;
        readers[i].chunksize = chunksize;
        readers[i].chunksizeRem = chunksizeRem;
        readers[i].firstThreadRem = firstThreadRem;
        readers[i].s = &shared;
    }
    
    unsigned long total_bytes_to_process = ((chunksize*readers_n*(portions_n))+(chunksizeRem*readers_n)+firstThreadRem);
    if(ifsize != total_bytes_to_process) {
        printf("Total input file bytes (%ld) mismatch after initial chunk processing %ld\n", ifsize, total_bytes_to_process);
        exit(EXIT_FAILURE);
    }

    /* Prepare writer thread data. */
    writer_data writer;
    writer.filesize = ifsize;
    if((writer.filepath = malloc(sizeof(char)*strlen(argv[input_file_i+1]))) == NULL)
        exit_with_sys_err("writer filepath malloc");
    strcpy(writer.filepath, argv[input_file_i+1]);
    writer.s = &shared;

    /* Create threads. */
    if((err = pthread_create(&writer.tid, NULL, writer_fn, &writer)) != 0)
        exit_with_err("pthread_create", err);
    for(unsigned int i = 0; i < readers_n; i++) {
        if((err = pthread_create(&readers[i].tid, NULL, reader_fn, &readers[i])) != 0)
            exit_with_err("pthread_create", err);
    }

    /* Wait for threads termination. */
    if((err = pthread_join(writer.tid, NULL)) != 0)
        exit_with_err("pthread_join", err);
    for(unsigned int i = 0; i < readers_n; i++) {
        if((err = pthread_join(readers[i].tid, NULL)) != 0)
            exit_with_err("pthread_join", err);
    }

    /* Destroy objects */
    if((err = pthread_mutex_destroy(&shared.mutex)) != 0)
        exit_with_err("pthread_mutex_destroy", err);
    if((err = pthread_cond_destroy(&shared.write)) != 0)
        exit_with_err("pthread_cond_destroy", err);
    for(unsigned int i = 0; i < readers_n; i++) {
        if((err = pthread_cond_destroy(&shared.readers[i])) != 0)
            exit_with_err("pthread_cond_destroy", err); 
    }

    /* Free allocated memory */
    free(writer.filepath);
    for(unsigned int i = 0; i < readers_n; i++) {
        free(readers[i].filepath);
    }
    free(shared.chunk);
    free(shared.readers);
    free(salt);
    free(key);
    free(iv);
    
    /* Total execution time in seconds. */
    long secs = (long)(time(NULL) - start);
    printf("\nFile %s in %ld seconds!\n", (dflag) ? "decrypted" : "encrypted", secs);
    
    exit(EXIT_SUCCESS);
}