#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define MAX_ARP_TABLE_SIZE 100

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

typedef struct {
    unsigned int len;
    char buff[MAX_PACKET_LEN];
    int interface;
    uint32_t route;
} packet_data;

typedef struct TrieNode {
    struct TrieNode *left;  // Represents bit 0
    struct TrieNode *right; // Represents bit 1
    struct route_table_entry *route; // Pointer to the route if this node represents a valid route
} TrieNode;

TrieNode *trie_root;

TrieNode *create_trie_node() {
    TrieNode *node = malloc(sizeof(TrieNode));
    node->left = NULL;
    node->right = NULL;
    node->route = NULL;
    return node;
}

void insert_route(TrieNode *root, struct route_table_entry *route) {
    TrieNode *current = root;
    uint32_t prefix = ntohl(route->prefix);
    uint32_t mask = ntohl(route->mask);

    for (int i = 31; i >= 0; i--) {
        if (!(mask & (1 << i))) {
            break;
        }

        if (prefix & (1 << i)) {
            if (!current->right) {
                current->right = create_trie_node();
            }
            current = current->right;
        } else {
            if (!current->left) {
                current->left = create_trie_node();
            }
            current = current->left;
        }
    }

    current->route = route;
}

TrieNode *build_trie(struct route_table_entry *rtable, int rtable_len) {
    TrieNode *root = create_trie_node();
    for (int i = 0; i < rtable_len; i++) {
        insert_route(root, &rtable[i]);
    }
    return root;
}

struct route_table_entry *search_trie(TrieNode *root, uint32_t dest_ip) {
    TrieNode *current = root;
    struct route_table_entry *best_route = NULL;
    uint32_t dest = ntohl(dest_ip);

    for (int i = 31; i >= 0; i--) {
        if (current->route) {
            best_route = current->route;
        }

        if (dest & (1 << i)) {
            if (!current->right) {
                break;
            }
            current = current->right;
        } else {
            if (!current->left) {
                break;
            }
            current = current->left;
        }
    }

    return best_route;
}

void free_trie(TrieNode *root) {
    if (!root) {
        return;
    }
    free_trie(root->left);
    free_trie(root->right);
    free(root);
}

struct route_table_entry *get_best_route(uint32_t dest) {
    return search_trie(trie_root, dest);
}

struct arp_table_entry *get_arp_table_entry(uint32_t dest_ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == dest_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void send_arp_request(uint32_t target_ip, size_t interface) {
    char buf[MAX_PACKET_LEN];
    struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    // Set Ethernet header
    memset(eth_hdr->ethr_dhost, 0xFF, 6); // Broadcast
    get_interface_mac(interface, eth_hdr->ethr_shost);
    eth_hdr->ethr_type = htons(0x0806); // ARP

    // Set ARP header
    arp_hdr->hw_type = htons(1); // Ethernet
    arp_hdr->proto_type = htons(0x0800); // IPv4
    arp_hdr->hw_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(1); // ARP Request
    get_interface_mac(interface, arp_hdr->shwa);
    arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
    memset(arp_hdr->thwa, 0x00, 6); // Unknown
    arp_hdr->tprotoa = target_ip;

    printf("Sending ARP Request: target_ip=%s, interface=%zu\n",
           inet_ntoa(*(struct in_addr *)&target_ip), interface);

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
}

void destroy_queue(queue q) {
    while (!queue_empty(q)) {
        free(queue_deq(q));
    }
    free(q);
}

void create_and_send_icmp_packet(char *buf, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hdr, uint8_t type, uint8_t code, int interface) {
    char reply_buf[MAX_PACKET_LEN];
    struct ether_hdr *reply_eth_hdr = (struct ether_hdr *)reply_buf;
    struct ip_hdr *reply_ip_hdr = (struct ip_hdr *)(reply_buf + sizeof(struct ether_hdr));
    struct icmp_hdr *reply_icmp_hdr = (struct icmp_hdr *)(reply_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    // Ethernet header
    memcpy(reply_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, reply_eth_hdr->ethr_shost);
    reply_eth_hdr->ethr_type = htons(ETHERTYPE_IP);

    // IP header
    reply_ip_hdr->ver = 4;
    reply_ip_hdr->ihl = 5;
    reply_ip_hdr->tos = 0;
    reply_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
    reply_ip_hdr->id = htons(0);
    reply_ip_hdr->frag = 0;
    reply_ip_hdr->ttl = 64;
    reply_ip_hdr->proto = 1; // ICMP
    reply_ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
    reply_ip_hdr->dest_addr = ip_hdr->source_addr;
    reply_ip_hdr->checksum = 0;
    reply_ip_hdr->checksum = htons(checksum((uint16_t *)reply_ip_hdr, sizeof(struct ip_hdr)));

    // ICMP header
    reply_icmp_hdr->mtype = 0;
    reply_icmp_hdr->mcode = 0;
    reply_icmp_hdr->check = 0;
    reply_icmp_hdr->check = htons(checksum((uint16_t *)reply_icmp_hdr, sizeof(struct icmp_hdr)));

    // ICMP reply
    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), reply_buf, interface);
}

void handle_arp_request(struct arp_hdr *arp_hdr, struct ether_hdr *eth_hdr, int interface) {
    if (arp_hdr->tprotoa != inet_addr(get_interface_ip(interface))) {
        return;
    }

    char reply_buf[MAX_PACKET_LEN];
    struct ether_hdr *reply_eth_hdr = (struct ether_hdr *)reply_buf;
    struct arp_hdr *reply_arp_hdr = (struct arp_hdr *)(reply_buf + sizeof(struct ether_hdr));

    // Ethernet header
    memcpy(reply_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, reply_eth_hdr->ethr_shost);
    reply_eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

    // ARP header
    reply_arp_hdr->hw_type = htons(1);
    reply_arp_hdr->proto_type = htons(ETHERTYPE_IP);
    reply_arp_hdr->hw_len = 6;
    reply_arp_hdr->proto_len = 4;
    reply_arp_hdr->opcode = htons(2); // ARP Reply
    get_interface_mac(interface, reply_arp_hdr->shwa);
    reply_arp_hdr->sprotoa = arp_hdr->tprotoa;
    memcpy(reply_arp_hdr->thwa, arp_hdr->shwa, 6);
    reply_arp_hdr->tprotoa = arp_hdr->sprotoa;

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), reply_buf, interface);
}

void handle_arp_reply(struct arp_hdr *arp_hdr, queue arp_queue) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == arp_hdr->sprotoa) {
            memcpy(arp_table[i].mac, arp_hdr->shwa, 6);
            return;
        }
    }

    if (arp_table_len < MAX_ARP_TABLE_SIZE) {
        arp_table[arp_table_len].ip = arp_hdr->sprotoa;
        memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
        arp_table_len++;
    }

    while (!queue_empty(arp_queue)) {
        packet_data *p = (packet_data *)queue_deq(arp_queue);
        if (p->route == arp_hdr->sprotoa) {
            struct ether_hdr *eth_hdr = (struct ether_hdr *)p->buff;
            memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
            get_interface_mac(p->interface, eth_hdr->ethr_shost);
            send_to_link(p->len, p->buff, p->interface);
            free(p);
        } else {
            queue_enq(arp_queue, p);
        }
    }
}

int decrement_ttl(char *buf, size_t interface) {
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    if (ip_hdr->ttl <= 1) {
        struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
        create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 11, 0, interface);
        return 0;
    }

    ip_hdr->ttl--;
    ip_hdr->checksum = 0;
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

    return 1;
}

int compare_routes(const void *a, const void *b) {
    struct route_table_entry *r1 = (struct route_table_entry *)a;
    struct route_table_entry *r2 = (struct route_table_entry *)b;

    if (ntohl(r1->prefix) != ntohl(r2->prefix)) {
        return (ntohl(r1->prefix) > ntohl(r2->prefix)) ? -1 : 1;
    }
    return (ntohl(r1->mask) > ntohl(r2->mask)) ? -1 : 1;
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);


    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    rtable_len = read_rtable(argv[1], rtable);
    trie_root = build_trie(rtable, rtable_len);
    arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_TABLE_SIZE);
    arp_table_len = 0;

    queue arp_queue = create_queue();

    while (1) {
        size_t len;
        int interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_link");

        struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

        if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_ARP) {
            struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
            if (ntohs(arp_hdr->opcode) == 1) {
                handle_arp_request(arp_hdr, eth_hdr, interface);
            } else if (ntohs(arp_hdr->opcode) == 2) {
                handle_arp_reply(arp_hdr, arp_queue);
            }
        } else if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_IP) {
            struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

            uint16_t received_checksum = ip_hdr->checksum;
            ip_hdr->checksum = 0;
            uint16_t calculated_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

            if (received_checksum != calculated_checksum) {
                continue;
            }

            ip_hdr->checksum = received_checksum;

            if (!decrement_ttl(buf, interface)) {
                continue;
            }

            if (ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))) {
                create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 0, 0, interface);
                continue;
            }

            struct route_table_entry *route = get_best_route(ip_hdr->dest_addr);
            if (!route) {
                create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 3, 0, interface);
                continue;
            }

            struct arp_table_entry *arp_entry = get_arp_table_entry(route->next_hop);
            if (!arp_entry) {
                packet_data *p = malloc(sizeof(packet_data));
                p->len = len;
                p->interface = route->interface;
                p->route = route->next_hop;
                memcpy(p->buff, buf, len);
                queue_enq(arp_queue, p);
                send_arp_request(route->next_hop, route->interface);
                continue;
            }

            memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
            get_interface_mac(route->interface, eth_hdr->ethr_shost);
            send_to_link(len, buf, route->interface);
        }
    }

    free(rtable);
    free(arp_table);
    destroy_queue(arp_queue);
    free_trie(trie_root);
    return 0;
}