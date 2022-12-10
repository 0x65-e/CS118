.DEFAULT_GOAL := crcExperiments
SHELL = /bin/bash

USERID=000000000

all: build

build: crcExperiments

crcExperiments: crcExperiments.cpp
	/usr/bin/g++ -Wall --std=c++11 -o crcExperiments crcExperiments.cpp

clean:
	@rm -f crcExperiments *.o *.tar.gz *.tar

dist: tarball
tarball: clean
	tar -cvf /tmp/$(USERID).tar crcExperiments.cpp Makefile README && mv /tmp/$(USERID).tar .
