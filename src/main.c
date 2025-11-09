#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asset-discovery.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <CIDR>\nExample: %s 192.168.1.0/24\n", argv[0], argv[0]);
        return 1;
    }
    const char *cidr = argv[1];

    printf("=== ARP cache scan (reading OS ARP table) ===\n");
    arp_entry_t *entries = NULL;
    int n = get_arp_entries(&entries);
    if (n < 0) {
        fprintf(stderr, "Error: failed to read ARP cache on this OS\n");
    } else if (n == 0) {
        printf("No ARP entries found (ARP cache empty). Try running a ping sweep to populate it.\n");
    } else {
        /* load OUI DB from ./oui.txt (project root) */
        char **prefixes = NULL;
        char **vendors = NULL;
        int oui_count = load_oui_db("./oui.txt", &prefixes, &vendors);
        if (oui_count < 0) {
            fprintf(stderr, "Warning: failed to load oui.txt\n");
            oui_count = 0;
        }

        printf("%-4s %-20s %-16s %-30s\n", "No.", "MAC Address", "IP Address", "Vendor");
        for (int i = 0; i < n; ++i) {
            const char *vendor = NULL;
            if (oui_count > 0) vendor = lookup_oui_vendor(entries[i].mac, prefixes, vendors, oui_count);
            printf("%-4d %-20s %-16s %-30s\n", i+1, entries[i].mac, entries[i].ip, vendor ? vendor : "Unknown");
        }

        /* free oui db */
        if (oui_count > 0) {
            for (int i = 0; i < oui_count; ++i) {
                free(prefixes[i]);
                free(vendors[i]);
            }
            free(prefixes);
            free(vendors);
        }
    }

    printf("\n=== CIDR expansion: %s ===\n", cidr);
    char **ips = NULL;
    int count = expand_cidr(cidr, &ips);
    if (count < 0) {
        fprintf(stderr, "Error: invalid CIDR or failed to expand\n");
    } else {
        printf("Expanded %d addresses. Writing to ./all_ips.txt\n", count);
        FILE *f = fopen("all_ips.txt", "w");
        if (!f) {
            fprintf(stderr, "Failed to open all_ips.txt for writing\n");
        } else {
            for (int i = 0; i < count; ++i) {
                fprintf(f, "%s\n", ips[i]);
            }
            fclose(f);
            printf("Wrote all_ips.txt (%d lines)\n", count);
        }
        /* free ips */
        for (int i = 0; i < count; ++i) free(ips[i]);
        free(ips);
    }

    if (entries) free(entries);
    return 0;
}
