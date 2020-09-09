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
#include <sys/stat.h>
#include <unistd.h>

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

    for (int i = 0; i < strlen(result); i++)
    {
        if (result[i] == ',')
        {
            result[i] = ' ';
        }
    }

    return result;
}

typedef struct info
{
    int cnt;
    char isp[1024];
    std::vector<std::string> timestamp;

} info;

typedef struct info2
{
    int cnt;
    vector<map<uint32_t, vector<string> > > data;

} info2;

void analysis_pcap(string &s_path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char pcap_name[1024] = {0};
    char path[1024] = {0};

    memcpy(path, s_path.c_str(), strlen(s_path.c_str()));
    memcpy(pcap_name, path, strlen(path));
    strncat(pcap_name, ".pcap", 5);

    pcap_t *handle = pcap_open_offline(pcap_name, errbuf);

    struct in_addr student_ip;
    struct in_addr cau_ip;

    inet_aton("211.252.81.120", &cau_ip);

    while (1)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        // time_t a = header->ts.tv_sec;
        // time_t b = header->ts.tv_usec;

        // printf("%lu %lu\n", a, b);

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

    int api_cnt = 0;

    while (1)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        cnt++;

        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        char buf[1024] = {
            0,
        };

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

        sprintf(buf, "%s", timestr);
        string capture_time(buf);

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
            api_cnt++;

            map_info[key].timestamp.push_back(capture_time);
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
            map_info[key].timestamp.push_back(capture_time);
        }

        if (api_cnt >= 45)
        {
            printf("sleep 60 ...\n");
            sleep(60);

            api_cnt = 0;
        }
    }

    for (map<uint32_t, info>::iterator it = map_info.begin(); it != map_info.end(); it++)
    {
        it->second.timestamp.erase(unique(it->second.timestamp.begin(), it->second.timestamp.end()), it->second.timestamp.end());
    }

    map<string, info2> map_info2;

    for (map<uint32_t, info>::iterator it = map_info.begin(); it != map_info.end(); it++)
    {
        string s_temp(it->second.isp);

        s_temp.erase(remove(s_temp.begin(), s_temp.end(), '/'), s_temp.end());

        map<uint32_t, vector<string> > m_temp;

        if (map_info2.find(s_temp) == map_info2.end())
        {
            map_info2[s_temp].cnt = it->second.cnt;
            m_temp[it->first] = it->second.timestamp;
            map_info2[s_temp].data.push_back(m_temp);
        }
        else
        {
            map_info2[s_temp].cnt += it->second.cnt;
            m_temp[it->first] = it->second.timestamp;
            map_info2[s_temp].data.push_back(m_temp);
        }
    }

    char file_name[1024] = {0};

    memcpy(file_name, path, strlen(path));
    strncat(file_name, "/", 1);

    char *student_id;

    char path_temp[1024] = {0};

    memcpy(path_temp, path, strlen(path));

    strtok(path_temp, "/");

    student_id = strtok(NULL, "/");
    student_id = strtok(NULL, "/");

    strncat(file_name, student_id, strlen(student_id));

    strncat(file_name, ".csv", 4);

    FILE *f = NULL;

    f = fopen(file_name, "w");

    fprintf(f, "isp, cnt\n");

    for (map<string, info2>::iterator it = map_info2.begin(); it != map_info2.end(); it++)
    {
        fprintf(f, "%s,%d\n", it->first.c_str(), it->second.cnt);
    }

    fclose(f);

    for (map<string, info2>::iterator it = map_info2.begin(); it != map_info2.end(); it++)
    {
        char isp_name[1024] = {0};
        char isp_str[1024] = {0};
        strcpy(isp_str, it->first.c_str());

        memcpy(isp_name, path, strlen(path));
        strncat(isp_name, "/", 1);
        strncat(isp_name, isp_str, strlen(isp_str));
        strncat(isp_name, ".csv", 4);

        FILE *f = NULL;

        f = fopen(isp_name, "w");

        fprintf(f, "ip, timestamp\n");

        for (vector<map<uint32_t, vector<string> > >::iterator i = it->second.data.begin(); i != it->second.data.end(); i++)
        {
            for (map<uint32_t, vector<string> >::iterator j = i->begin(); j != i->end(); j++)
            {
                fprintf(f, "%s,", inet_ntoa(*(struct in_addr *)(&j->first)));
                for (vector<string>::iterator k = j->second.begin(); k != j->second.end(); k++)
                {
                    fprintf(f, "%s,", k->c_str());
                }
                fprintf(f, "\n");
            }
        }

        fclose(f);
    }

    fclose(f);

    pcap_close(handle);

    printf("%s Finish\n", path);
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

        if (!(strncmp(dir->d_name + strlen(dir->d_name) - 5, ".pcap", 5)))
        {
            v.push_back(dir->d_name);
        }
    }

    closedir(dp);

    for (iter = v.begin(); iter != v.end(); iter++)
    {
        string s_path(path);
        s_path += "/";
        s_path += *iter;

        int len = s_path.size();
        s_path = s_path.substr(0, len - 5);

        char stu_path[1024] = {
            0,
        };

        memcpy(stu_path, s_path.c_str(), strlen(s_path.c_str()));

        mkdir(stu_path, 755);

        analysis_pcap(s_path);
    }

    return 0;
}