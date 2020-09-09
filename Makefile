all: pcap
CC = g++

pcap: pcap2.cpp
	$(CC) -o $@ $< -lpcap


clean:
	rm -f pcap
