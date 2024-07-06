#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_SIZE 14
#define SMB2_PROTOCOL_ID 0xFE534D42

void extract_smb2_info(const u_char *packet, struct pcap_pkthdr packet_header, FILE *output_file) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_SIZE);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHERNET_HEADER_SIZE + (ip_header->ip_hl * 4));
    const u_char *payload = packet + ETHERNET_HEADER_SIZE + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
    int payload_length = packet_header.len - (ETHERNET_HEADER_SIZE + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));

    if (payload_length > 4) {
        uint32_t protocol_id = ntohl(*(uint32_t *)payload);
        if (protocol_id == SMB2_PROTOCOL_ID) {
            uint16_t command = ntohs(*(uint16_t *)(payload + 12));
            if (command == 0x05) {  // SMB2 Create Request
                fprintf(output_file, "{\n");
                fprintf(output_file, "  \"command\": \"Create Request\",\n");
                fprintf(output_file, "  \"src_ip\": \"%s\",\n", inet_ntoa(ip_header->ip_src));
                fprintf(output_file, "  \"src_port\": \"%d\",\n", ntohs(tcp_header->th_sport));
                fprintf(output_file, "  \"dst_ip\": \"%s\",\n", inet_ntoa(ip_header->ip_dst));
                fprintf(output_file, "  \"dst_port\": \"%d\",\n", ntohs(tcp_header->th_dport));
                fprintf(output_file, "  \"timestamp\": \"%ld.%06d\"\n", packet_header.ts.tv_sec, packet_header.ts.tv_usec);

                uint16_t name_offset = ntohs(*(uint16_t *)(payload + 52));
                uint16_t name_length = ntohs(*(uint16_t *)(payload + 54));
                if (name_offset + name_length <= payload_length) {
                    char file_name[256];
                    memcpy(file_name, payload + name_offset, name_length);
                    file_name[name_length] = '\0';
                    fprintf(output_file, "  \"file_name\": \"%s\"\n", file_name);
                } else {
                    fprintf(output_file, "  \"file_name\": \"N/A\"\n");
                }

                fprintf(output_file, "},\n");
            }
        }
    }
}

void process_pcap(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", pcap_file, errbuf);
        exit(1);
    }

    FILE *output_file = fopen("smb2_create_requests_metadata.json", "w");
    if (output_file == NULL) {
        fprintf(stderr, "Could not open output file\n");
        exit(1);
    }
    fprintf(output_file, "[\n");

    struct pcap_pkthdr packet_header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &packet_header)) != NULL) {
        extract_smb2_info(packet, packet_header, output_file);
    }

    fprintf(output_file, "]\n");
    fclose(output_file);

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    process_pcap(argv[1]);

    return 0;
}
