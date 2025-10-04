CC = gcc
CFLAGS = -Wall -Wextra -g
SRC = encryptor.c
TARGET = encryptor

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm $(TARGET)
