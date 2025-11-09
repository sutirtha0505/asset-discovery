#ifndef ASSET_DISCOVERY_H
#define ASSET_DISCOVERY_H

#include <stddef.h>

typedef struct {
    char ip[16];   /* dotted IPv4 */
    char mac[32];  /* mac format: xx:xx:xx:xx:xx:xx or xx-xx-.. */
} arp_entry_t;

/* Get ARP entries (reads system ARP cache). Returns number of entries.
 * entries_out: pointer to dynamically allocated array of arp_entry_t (must be free()'d by caller).
 * On error returns -1.
 */
int get_arp_entries(arp_entry_t **entries_out);

/* Expand an IPv4 CIDR (e.g. "192.168.1.0/24") into a dynamically allocated
 * array of dotted IPv4 strings. Returns count on success, -1 on error.
 * ips_out: pointer to char** allocated by function; caller must free each string and free(ips_out).
 */
int expand_cidr(const char *cidr, char ***ips_out);

/* Convert uint32 ip (host order) to dotted string into buf (>=16 bytes) */
void uint32_to_ipstr(unsigned int ip, char *buf);

/* Convert dotted IPv4 to uint32 host order. Returns 0 on success, -1 on error. */
int ipstr_to_uint32(const char *ipstr, unsigned int *out);

/* ---------------- OUI/vendor helpers ---------------- */

/* Load OUI database from path (e.g. "./oui.txt"). Returns number of loaded prefixes,
 * returns -1 on error. The function allocates *prefixes_out and *vendors_out arrays:
 *   prefixes_out -> array of N strings (each 6 hex chars, uppercase, no separators), e.g. "28AABB"
 *   vendors_out  -> array of N strings (vendor names)
 * Caller must free each string in prefixes_out/vendors_out and free the arrays themselves.
 */
int load_oui_db(const char *path, char ***prefixes_out, char ***vendors_out);

/* Given a MAC like "00:11:22:33:44:55" or "00-11-22-33-44-55", returns vendor string pointer
 * from loaded arrays, or NULL if not found. Does NOT allocate. */
const char *lookup_oui_vendor(const char *mac, char * const *prefixes, char * const *vendors, int count);

#endif /* ASSET_DISCOVERY_H */
