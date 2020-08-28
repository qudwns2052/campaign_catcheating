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
#include <dirent.h>
#include <vector>

#define BUF_SIZE 1024

#pragma pack(push, 1)

using namespace std;

#pragma pack(pop)

void usage(void)
{
    fprintf(stderr, "Usage: <pcap filename>\n");
    exit(2);
}
char *get_isp(char *ip)
{
    FILE *fp;
    char path[BUF_SIZE];

    char curl[1024] = "curl ip-api.com/json/";

    strncat(curl, ip, 15);

    char trash[1024] = " 2>/dev/null";

    strncat(curl, trash, 15);

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

typedef struct info
{
    int cnt;
    char isp[1024];
} info;


void analysis_pcap(string & s_pcap_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char pcap_name[1024];

    memcpy(pcap_name, s_pcap_name.c_str(), strlen(s_pcap_name.c_str()));

    pcap_t *handle = pcap_open_offline(pcap_name, errbuf);



    struct in_addr student_ip;
    struct in_addr cau_ip;

    inet_aton("211.252.81.120", &cau_ip);

    while (1)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        struct ether_header *eth = (struct ether_header *)(packet);

        if (eth->ether_type != htons(ETHERTYPE_IP))
            continue;

        const struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);

        if (memcmp(&ip->ip_src, &cau_ip, 4) == 0)
        {
            memcpy(&student_ip, &ip->ip_dst, 4);
            break;
        }
        else if (memcmp(&ip->ip_dst, &cau_ip, 4) == 0)
        {
            memcpy(&student_ip, &ip->ip_src, 4);
            break;
        }
        else
            continue;
    }

    char ip_str[BUF_SIZE] = {0};
    int cnt = 0;

    uint32_t key;

    map<uint32_t, info> map_info;

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

        if (memcmp(&ip->ip_src, &student_ip, 4) == 0)
        {
            memcpy(&key, &ip->ip_dst, 4);
        }
        else
        {
            memcpy(&key, &ip->ip_src, 4);
        }

        if (map_info.find(key) == map_info.end())
        {
            map_info[key].cnt = 1;
            char *t1 = inet_ntoa(*(struct in_addr *)(&key));
            char *t2 = get_isp(t1);

            if (t2 == NULL)
            {
                memcpy(map_info[key].isp, "NULL", 5);
            }
            else
            {
                memcpy(map_info[key].isp, t2, strlen(t2));
            }
        }
        else
        {
            map_info[key].cnt++;
        }
    }

    char *file_name = (char *)malloc(sizeof(char) * strlen(pcap_name) + 1);
    memcpy(file_name, pcap_name, strlen(pcap_name));


    strtok(file_name, ".");
    strncat(file_name, ".csv", 4);
    file_name[strlen(file_name)] = '\0';

    FILE *f = NULL;

    f = fopen(file_name, "w");

    fprintf(f, "ip address, isp, cnt (total = %d)\n", cnt - 1);

    for (map<uint32_t, info>::iterator it = map_info.begin(); it != map_info.end(); it++)
    {
        fprintf(f, "%s,%s,%d\n", inet_ntoa(*(struct in_addr *)(&it->first)),
                it->second.isp, it->second.cnt);
    }

    pcap_close(handle);

    fclose(f);

    printf("%s Finish\n", pcap_name);
}



int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: <pcap directory name>\n");
        exit(2);
    }

    DIR *dp;
    struct dirent *dir;
    std::vector<std::string> v;
    std::vector<std::string>::iterator iter;

    char path[1024] = "./";
    strncat(path, argv[1], strlen(argv[1]) + 1);

    if ((dp = opendir(path)) == NULL)
    {
        fprintf(stderr, "%s is not exist path\n", path);
        exit(-1);
    }

    while ((dir = readdir(dp)) != NULL)
    {
        if (dir->d_ino == 0)
            continue;

        v.push_back(dir->d_name);
    }

    closedir(dp);

    iter = v.begin();

    v.erase(iter, iter + 2);

    for (iter = v.begin(); iter != v.end(); iter++)
    {
        string pcap_name(path);
        pcap_name += "/";
        pcap_name += *iter;
        analysis_pcap(pcap_name);
    }

    return 0;
}