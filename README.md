# Data Plane Router
### Balaniuc Rodion 325CB

## Prezentare generală

Acest router realizează forwarding-ul de pachete între interfețele de rețea folosind:
- Longest Prefix Match pentru rutare eficientă
- Protocolul ARP pentru rezolvarea adreselor
- ICMP pentru mesaje de eroare și control

## 1. Implementarea Longest Prefix Match

Am implementat un arbore binar (trie) pentru a găsi rapid cea mai bună rută potrivită pentru adresele IP destinație. Acest algoritm este mult mai eficient decât o căutare liniară în tabela de rutare.

```c
typedef struct TrieNode {
    struct TrieNode *left;   // 0 bit
    struct TrieNode *right;  // 1 bit 
    struct route_table_entry *route;
} TrieNode;

TrieNode *build_trie(struct route_table_entry *rtable, int rtable_len) {
    TrieNode *root = create_trie_node();
    for (int i = 0; i < rtable_len; i++) {
        insert_route(root, &rtable[i]);
    }
    return root;
}
```

## 2. Protocolul ARP

Routerul gestionează două aspecte ale ARP:
1. Răspunde la cererile ARP primite
2. Inițiază cereri ARP când are nevoie să afle adresa MAC corespunzătoare unei adrese IP

```c
void send_arp_request(uint32_t target_ip, size_t interface) {
    // Construiește header Ethernet (broadcast)
    // Construiește header ARP (request)
    // Trimite pachetul
}

void handle_arp_reply(struct arp_hdr *arp_hdr, queue arp_queue) {
    // Actualizează tabela ARP
    // Procesează pachetele în așteptare
}
```

## 3. Protocolul ICMP

Routerul generează mesaje ICMP în următoarele situații:
- Destinația este unreachable (tip 3)
- TTL a expirat (tip 11)
- Echo reply (tip 0)

```c
void create_and_send_icmp_packet(char *buf, struct ether_hdr *eth_hdr, 
                               struct ip_hdr *ip_hdr, uint8_t type, 
                               uint8_t code, int interface) {
    // Construiește header Ethernet
    // Construiește header IP 
    // Construiește header ICMP
    // Calculează checksum
    // Trimite pachetul
}
```

## 4. Fluxul principal

Funcția main gestionează:
- Inițializarea structurilor de date
- Primirea pachetelor
- Dirijarea pe baza tipului de pachet (ARP/IP)

```c
int main() {
    // Inițializare tabelă de rutare și ARP
    while (1) {
        // Așteaptă pachet
        if (pachet ARP) {
            // Procesează cerere/răspuns ARP
        } else if (pachet IP) {
            // Verifică checksum
            // Scade TTL
            // Găsește cea mai bună rută
            // Trimite pachetul
        }
    }
}
```

## Concluzie

Această implementare realizează toate funcționalitățile de bază ale unui router:
- Rutare eficientă folosind trie
- Rezolvare adrese MAC prin ARP
- Generare mesaje ICMP pentru gestionarea erorilor
- Forwarding corect al pachetelor IP
