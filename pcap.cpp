#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <map>

#define BUF_SIZE 1024

#pragma pack(push, 1)

using namespace std;

#pragma pack(pop)

char *get_isp(char *ip)
{
    FILE *fp;
    char path[BUF_SIZE];

    char curl[1024] = "curl ip-api.com/json/";

    strncat(curl, ip, 15);

    fp = popen(curl, "r");

    if (fp == NULL)
    {
        printf("Failed to run command\n");
        exit(1);
    }

    char json[BUF_SIZE] = {
        0,
    };

    while (fgets(path, sizeof(path), fp) != NULL)
    {
        strcat(json, path);
    }

    pclose(fp);

    char *isp_temp = nullptr;
    char *isp = nullptr;

    isp_temp = strstr(json, "isp");

    if (isp_temp == NULL)
        return nullptr;

    strtok(isp_temp, "\"");
    isp = strtok(NULL, "\"");
    isp = strtok(NULL, "\"");

    char *result = (char *)malloc(sizeof(char) * strlen(isp) + 1);

    memcpy(result, isp, strlen(isp) + 1);

    return result;
}

typedef struct abc
{
    int cnt;
    char isp[1024];
} abc;

int main(int argc, char *argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline("nono.pcap", errbuf);

    struct in_addr student_ip;
    struct in_addr cau_ip;
    //    struct in_addr gw_ip;

    inet_aton(argv[1], &student_ip);
    inet_aton("211.252.81.120", &cau_ip);
    //    inet_aton("172.30.1.1", &gw_ip);

    char ip_str[BUF_SIZE] = {0};
    int cnt = 0;

    uint32_t key;

    map<uint32_t, abc> info;

    while (1)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        cnt++;

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        struct ether_header *eth = (struct ether_header *)(packet);

        if (eth->ether_type != htons(ETHERTYPE_IP))
            continue;

        const struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);

        if (memcmp(&ip->ip_src, &ip->ip_dst, 4) == 0)
            continue;

        if ((memcmp(&ip->ip_src, &cau_ip, 4) == 0) || (memcmp(&ip->ip_dst, &cau_ip, 4) == 0))
            continue;

        if (memcmp(&ip->ip_src, &student_ip, 4) == 0)
        {
            memcpy(&key, &ip->ip_dst, 4);
        }
        else
        {
            memcpy(&key, &ip->ip_src, 4);
        }

        // if (memcmp(&key, &gw_ip, 4) == 0)
        //     continue;

        if (info.find(key) == info.end())
        {
            info[key].cnt = 1;
            char *t1 = inet_ntoa(*(struct in_addr *)(&key));
            char *t2 = get_isp(t1);

            if (t2 == NULL)
            {
                printf("NULL!\n");
                memcpy(info[key].isp,"NULL",5);
            }
            else
            {
                printf("isp = %s\n", t2);
                memcpy(info[key].isp, t2, strlen(t2));
            }

            printf("hello\n");
        }
        else
        {
            info[key].cnt++;
        }
    }

    FILE *f = NULL;
    f = fopen("result.csv", "w");

    fprintf(f, "ip address, isp, cnt (total = %d)\n", cnt - 1);

    for (map<uint32_t, abc>::iterator it = info.begin(); it != info.end(); it++)
    {
        fprintf(f, "%s,%s,%d\n", inet_ntoa(*(struct in_addr *)(&it->first)),
                it->second.isp, it->second.cnt);
    }

    pcap_close(handle);

    fclose(f);
    return 0;
}