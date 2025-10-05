CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto -lpthread
SRC = encryptor.c
TARGET = encryptor

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm $(TARGET)
