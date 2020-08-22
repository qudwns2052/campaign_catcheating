all: pcap
CC = g++

pcap: pcap.cpp
	$(CC) -o $@ $< -lpcap


clean:
	rm -f pcap
