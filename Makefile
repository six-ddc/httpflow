
default: all

CXXFLAGS=-O2 -I/usr/local/include
LIBS=-lz -lpcap -lpcre

PREFIX?=/usr/local
INSTALL_BIN=$(PREFIX)/bin

INSTALL=install

HTTPFLOW_BIN=httpflow

http_flow.o: http_flow.cpp
	$(CXX) $(CXXFLAGS) -c http_flow.cpp -o http_flow.o

custom_parser.o: custom_parser.cpp
	$(CXX) $(CXXFLAGS) -c custom_parser.cpp -o custom_parser.o

util.o: util.cpp
	$(CXX) $(CXXFLAGS) -c util.cpp -o util.o

data_link.o: data_link.cpp
	$(CXX) $(CXXFLAGS) -c data_link.cpp -o data_link.o

http_parser.o: http_parser.cpp
	$(CXX) $(CXXFLAGS) -c http_parser.cpp -o http_parser.o

all: http_flow.o http_parser.o custom_parser.o util.o data_link.o
	$(CXX) $(LIBS) http_flow.o http_parser.o custom_parser.o util.o data_link.o -o $(HTTPFLOW_BIN)
	
install:
	@mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(HTTPFLOW_BIN) $(INSTALL_BIN)

clean:
	rm -rf $(HTTPFLOW_BIN) *.o

.PHONY: install all clean
