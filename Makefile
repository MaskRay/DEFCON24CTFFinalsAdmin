CXXFLAGS := -g3 -std=c++11

all: wait2
wait2: wait2.cc
	$(LINK.cc) -m32 $^ -o $@

packet-log: packet-log.cc
