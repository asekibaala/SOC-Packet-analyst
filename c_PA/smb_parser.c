#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SMB2_PROTOCOL_ID 0xfe534d42
#define SMB2_CREATE_REQUEST 0x05

typedef struct smb_metadata {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    double timestamp;
} smb_metadata_t;

typedef struct smb_packet {
    uint8_t *data;
    smb_metadata_t metadata;
} smb_packet_t;

void parse_smb_packet(const uint8_t *packet, smb_packet_t *smb_packet, struct pcap_pkthdr *header) {
    const struct ip *ip_header = (struct ip *)(packet + 14);
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
    const uint8_t *payload = (uint8_t *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4);

    uint32_t protocol_id = *(uint32_t *)payload;
    if (protocol_id == SMB2_PROTOCOL_ID) {
        uint16_t command = *(uint16_t *)(payload + 12);
        if (command == SMB2_CREATE_REQUEST) {
            smb_packet->data = (uint8_t *)malloc(header->caplen - (payload - packet));
            memcpy(smb_packet->data, payload, header->caplen - (payload - packet));
            
            inet_ntop(AF_INET, &(ip_header->ip_src), smb_packet->metadata.src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), smb_packet->metadata.dst_ip, INET_ADDRSTRLEN);
            smb_packet->metadata.src_port = ntohs(tcp_header->th_sport);
            smb_packet->metadata.dst_port = ntohs(tcp_header->th_dport);
            smb_packet->metadata.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1e6;
        }
    }
}

void process_pcap(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const uint8_t *packet;
    smb_packet_t smb_packets[1000];
    int smb_packet_count = 0;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        smb_packet_t smb_packet;
        parse_smb_packet(packet, &smb_packet, &header);
        if (smb_packet.data != NULL) {
            smb_packets[smb_packet_count++] = smb_packet;
        }
    }

    pcap_close(handle);

    FILE *output_file = fopen("smb_packets.json", "w");
    if (output_file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fprintf(output_file, "[\n");
    for (int i = 0; i < smb_packet_count; ++i) {
        fprintf(output_file, "  {\n");
        fprintf(output_file, "    \"src_ip\": \"%s\",\n", smb_packets[i].metadata.src_ip);
        fprintf(output_file, "    \"dst_ip\": \"%s\",\n", smb_packets[i].metadata.dst_ip);
        fprintf(output_file, "    \"src_port\": %d,\n", smb_packets[i].metadata.src_port);
        fprintf(output_file, "    \"dst_port\": %d,\n", smb_packets[i].metadata.dst_port);
        fprintf(output_file, "    \"timestamp\": %.6f,\n", smb_packets[i].metadata.timestamp);
        fprintf(output_file, "    \"data\": \"");
        for (int j = 0; j < header.caplen; ++j) {
            fprintf(output_file, "%02x", smb_packets[i].data[j]);
        }
        fprintf(output_file, "\"\n");
        fprintf(output_file, "  }%s\n", (i == smb_packet_count - 1) ? "" : ",");
    }
    fprintf(output_file, "]\n");

    fclose(output_file);

    for (int i = 0; i < smb_packet_count; ++i) {
        free(smb_packets[i].data);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    process_pcap(argv[1]);

    return EXIT_SUCCESS;
}
