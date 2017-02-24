
default: all

CXXFLAGS=-O2
LIBS=-lz -lpcap

PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin

INSTALL=install

HTTPFLOW_BIN=httpflow

http_flow.o: http_flow.cpp
	$(CXX) $(CXXFLAGS) -c http_flow.cpp -o http_flow.o

http_parser.o: http_parser.cpp
	$(CXX) $(CXXFLAGS) -c http_parser.cpp -o http_parser.o

all: http_flow.o http_parser.o
	$(CXX) $(LIBS) http_flow.o http_parser.o -o $(HTTPFLOW_BIN)
	
install:
	@mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(HTTPFLOW_BIN) $(INSTALL_BIN)

clean:
	rm -rf $(HTTPFLOW_BIN) *.o

.PHONY: install all clean
