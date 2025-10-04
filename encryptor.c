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

/* Maximum file chunk size processable by . */
#define MAX_READER_CHUNK_SIZE 1024*1024*16
/* Minimum file size to enable multithread execution. */
#define MIN_FILE_SIZE (1024*16) + 1

#define exit_with_sys_err(err) {    \
    perror(err);                    \
    exit(EXIT_FAILURE);             \
}

#define exit_with_err(str, err) {                   \
    fprintf(stderr, "%s: %s", str, strerror(err));  \
    exit(EXIT_FAILURE);                             \
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
    char *chunk;
    unsigned int turn; /* reader thread index inside array */
    unsigned int readers_n; /* total reader threads */
    unsigned int readers_exited; /* reader threads terminated */
    bool written; /* writer work flag */
    bool fetched; /* reader work flag */
} shared_data;

typedef struct {
    pthread_t tid;
    unsigned int id;
    unsigned long portions_n;
    size_t chunksize;
    size_t chunksizeRem; /* remaining bytes from division among reader(s)  */
    size_t firstThreadRem; /* remaining bytes read only by the first reader */
    char *filepath;
    // shared
    shared_data *s;    
} reader_data;

typedef struct {
    pthread_t tid;
    char *filepath;
    size_t filesize;
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
        char *c; /* chunk */
        size_t csize; /* chunk size*/
        if(i == 0)
            csize = data->chunksize+data->chunksizeRem;
        else
            csize = data->chunksize;
        
        if((c = malloc(sizeof(char)*csize)) == NULL)
            exit_with_sys_err("reader chunk malloc");
        
        size_t portionStartIndex = (csize*data->s->readers_n*i);
        if(i > 0) portionStartIndex += (data->chunksizeRem*data->s->readers_n);
        size_t offset = (portionStartIndex + (csize*data->id));
        
        if(lseek(fd, offset, SEEK_SET) == -1)
            exit_with_sys_err("reader lseek");

        /* Read chunk from file. */
        if(read(fd, c, csize) == -1)
            exit_with_sys_err("reader read");

        mutex_lock(&data->s->mutex);

        /* Wait for its turn. */
        while(data->s->turn != data->id)
            cond_wait(&data->s->readers[data->id], &data->s->mutex);
        if((data->s->chunk = realloc(data->s->chunk, sizeof(char)*csize)) == NULL)
            exit_with_sys_err("reader realloc shared chunk");
        memcpy(data->s->chunk, c, csize);
        free(c);
        data->s->chunksize = csize;
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
        if(lseek(fd, offset, SEEK_SET) == -1)
            exit_with_sys_err("reader final lseek");

        if((data->s->chunk = realloc(data->s->chunk, sizeof(char)*data->firstThreadRem)) == NULL)
            exit_with_sys_err("reader realloc shared chunk");
        /* Read chunk from file. */
        if(read(fd, data->s->chunk, data->firstThreadRem) == -1)
            exit_with_sys_err("reader read");

        data->s->chunksize = data->firstThreadRem;
        data->s->offset = offset;
        data->s->fetched = true;
    } 
    else {
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
    if((fd = open(data->filepath, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR)) == -1)
        exit_with_sys_err("writer open file");
    mutex_lock(&data->s->mutex);
    size_t sum = 0;
    while(1) {
        while(data->s->fetched == false && data->s->readers_exited < data->s->readers_n)
            cond_wait(&data->s->write, &data->s->mutex);

        if(lseek(fd, data->s->offset, SEEK_SET) == -1)
            exit_with_sys_err("writer lseek");
        if(write(fd, data->s->chunk, data->s->chunksize) == -1)
            exit_with_sys_err("writer write");
        sum += data->s->chunksize;
        /* All readers exited. End of work. */
        if(data->s->readers_exited == data->s->readers_n) {
            break;
        }
        data->s->written = true;
        data->s->fetched = false;
        /* Wake reader */
        cond_signal(&data->s->write);

        // Print loading percentage
        if(data->filesize > 0) {
            printf("\rCopying... %d%%", (int)((sum*100)/data->filesize));
            fflush(stdout); // Flush the output buffer
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

    bool dflag = false; // Decrypt flag
    if(strcmp(argv[1], "-d") == 0) {
        dflag = true;
    }

    int input_file_i = 1;
    if(dflag) input_file_i++; 

    struct stat inputf; /* Input file stat */
    if((stat(argv[input_file_i], &inputf) == -1))
        exit_with_sys_err("stat");

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
    unsigned long chunksize = 0;
    /* Remaining bytes to read only within 1 portion of the file (the first one) */
    unsigned long chunksizeRem = 0;
    /* Any remaining bytes after bytes distribution among threads that must be
     * read only once by the FIRST thread. */
    unsigned long firstThreadRem = 0;

    /* Run using a single thread. */
    if(inputf.st_size < MIN_FILE_SIZE) {
        readers_n = 1;
        req_mem = inputf.st_size;
        chunksize = inputf.st_size;
    } 
    /* All the `readers_n` threads will process the input file. */
    else {
        /* File is made up by only 1 portion. */
        if(inputf.st_size <= portion_max_size) {
            chunksize = (inputf.st_size / readers_n);
            /* Add any remaining bytes to read to the first reader thread. */
            if(inputf.st_size % readers_n > 0) {
                firstThreadRem = (inputf.st_size % readers_n);
            }
            req_mem = inputf.st_size;
        }
        /* File is made up by more than 1 portion. */
        else {
            req_mem = portion_max_size;

            portions_n = (unsigned int)(inputf.st_size / portion_max_size);
            chunksize = MAX_READER_CHUNK_SIZE;
            /* Add any extra bytes caused by divisions remainders: first reader thread might read
             * a bigger chunk than others (if there are any divisions reminders) */
            unsigned long rem = inputf.st_size % portion_max_size;
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

    printf("File: %s (%lu bytes)... \n", argv[input_file_i], inputf.st_size);
    printf("File split in %u portions\n", portions_n);
    printf("File Portion size %lu bytes \n", (inputf.st_size > portion_max_size) ? portion_max_size: inputf.st_size);
    printf("CPU cores: %lu\n", cpu_cores_n);
    printf("Starting %u threads; %u readers, %u writer\n", readers_n+1, readers_n, 1);

    /* Prepare shared data among threads. */
    shared_data shared;
    shared.turn = 0;
    shared.written = false;
    shared.fetched = false;
    shared.readers_exited = 0;
    shared.readers_n = readers_n;
    shared.chunk = NULL;
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
    if(inputf.st_size != total_bytes_to_process) {
        printf("Total input file bytes (%ld) mismatch after initial chunk processing %ld\n", inputf.st_size, total_bytes_to_process);
        exit(EXIT_FAILURE);
    }

    /* Prepare writer thread data. */
    writer_data writer;
    writer.filesize = inputf.st_size;
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
    
    printf("\nFile copied!\n");
    
    exit(EXIT_SUCCESS);
}