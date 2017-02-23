
default: all

CXXFLAGS=-std=c++11 -O2
LIBS=-lz -lpcap

PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin

INSTALL=install

HTTPFLOW_BIN=httpflow

httpflow.o:
	$(CXX) $(CXXFLAGS) -c httpflow.cpp -o httpflow.o

http_parser.o:
	$(CXX) $(CXXFLAGS) -c http_parser.cpp -o http_parser.o

all: httpflow.o http_parser.o
	@echo "make all"
	$(CXX) $(LIBS) httpflow.o http_parser.o -o $(HTTPFLOW_BIN)
	
$(HTTPFLOW_BIN):
	@echo "make $(HTTPFLOW_BIN)"

install:
	@echo "make install"
	@mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(HTTPFLOW_BIN) $(INSTALL_BIN)

clean:
	@echo "make clean"
	rm -rf $(HTTPFLOW_BIN) *.o

.PHONY: install all clean
