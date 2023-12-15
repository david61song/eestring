# EEstring Makefile
#
#
OS := $(shell uname -s)

CC := gcc # Linux (Ubuntu)
ifeq ($(OS),Darwin) # macOS
	CC := clang
endif

# Check if pkg-config installed. If not, install pkg-config
#

CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
LFLAGS := $(shell pkg-config --libs-only-L openssl 2>/dev/null)
LIBS := -lcrypto -lssl -lpthread 

CFLAGS += -Wno-deprecated

CLISRCS := client_method.c socket.c tls.c list.c packet.c encrypt.c
SERVERSRCS := server_method.c socket.c tls.c list.c packet.c encrypt.c

all: server cli check-requirements

check-requirements:
	@bash check_requirements.sh || (echo "Requirements check failed. Run check_requirements.sh" && false)

# Build server
server: relay_server.c $(SRCS) check-requirements
	$(CC) -o server relay_server.c $(SERVERSRCS) $(CFLAGS) $(LFLAGS) $(LIBS)

# Build Cli
cli: client.c $(SRCS) check-requirements
	$(CC) -o cli client.c $(CLISRCS) $(CFLAGS) $(LFLAGS) -lcrypto -lssl -lpthread 

# Clean executables
clean:
	rm -f server cli

# Create some certificate for TLS connection.
init:
	bash make_cert.sh

# Clean Cert, Debug file, and executables.
fclean: clean
	rm -rf *.dSYM
	bash clear_cert.sh

re: clean all
