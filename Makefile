# Makefile for the Bit-in-the-Middle binary HTTP project.
#   make            build both bserve and bcurl
#   make bserve     build the server only
#   make bcurl      build the client only
#   make clean      remove build output

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS += -Iinclude

.PHONY: all clean
all: bserve bcurl

bserve: src/bserve.cpp include/protocol.hpp include/frame_io.hpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) src/bserve.cpp -o $@

bcurl: src/bcurl.cpp include/protocol.hpp include/frame_io.hpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) src/bcurl.cpp -o $@

clean:
	rm -f bserve bcurl
