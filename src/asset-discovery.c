#define _CRT_SECURE_NO_WARNINGS
#include "asset-discovery.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <stdio.h>
#else
#include <unistd.h>
#endif

/* -------------------- Utility: IP conversions -------------------- */
static int parse_octet(const char *p, int *len, unsigned *octet) {
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    if (v < 0 || v > 255) return -1;
    *len = (int)(end - p);
    *octet = (unsigned)v;
    return 0;
}

int ipstr_to_uint32(const char *ipstr, unsigned int *out) {
    if (!ipstr || !out) return -1;
    unsigned o[4];
    const char *p = ipstr;
    for (int i = 0; i < 4; ++i) {
        int len;
        if (parse_octet(p, &len, &o[i]) != 0) return -1;
        p += len;
        if (i < 3) {
            if (*p != '.') return -1;
            ++p;
        }
    }
    if (*p != '\0') return -1;
    *out = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
    return 0;
}

void uint32_to_ipstr(unsigned int ip, char *buf) {
    unsigned o0 = (ip >> 24) & 0xFFU;
    unsigned o1 = (ip >> 16) & 0xFFU;
    unsigned o2 = (ip >> 8) & 0xFFU;
    unsigned o3 = ip & 0xFFU;
    sprintf(buf, "%u.%u.%u.%u", o0, o1, o2, o3);
}

/* -------------------- CIDR expansion -------------------- */
int expand_cidr(const char *cidr, char ***ips_out) {
    if (!cidr || !ips_out) return -1;
    /* split on '/' */
    const char *s = strchr(cidr, '/');
    if (!s) return -1;
    size_t base_len = (size_t)(s - cidr);
    if (base_len >= 32) return -1;

    char base[32];
    strncpy(base, cidr, base_len);
    base[base_len] = '\0';
    int prefix = atoi(s + 1);
    if (prefix < 0 || prefix > 32) return -1;

    unsigned base_ip;
    if (ipstr_to_uint32(base, &base_ip) != 0) return -1;

    unsigned hostbits = (prefix == 32) ? 0U : (32U - (unsigned)prefix);
    unsigned count = (hostbits == 0) ? 1U : (1U << hostbits);
    /* allocate array of char* */
    char **arr = (char **)malloc(sizeof(char *) * (size_t)count);
    if (!arr) return -1;
    for (unsigned i = 0; i < count; ++i) {
        arr[i] = (char *)malloc(16);
        if (!arr[i]) {
            for (unsigned j = 0; j < i; ++j) free(arr[j]);
            free(arr);
            return -1;
        }
        unsigned ip = base_ip + i;
        uint32_to_ipstr(ip, arr[i]);
    }
    *ips_out = arr;
    return (int)count;
}

/* -------------------- ARP cache reading & parsing -------------------- */

/* Helper: trim leading/trailing spaces */
static char *trim(char *s) {
    if (!s) return s;
    while (isspace((unsigned char)*s)) ++s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

#ifdef __linux__
/* Parse lines like:
   192.168.1.10 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
   or fallback arp -n: 192.168.1.10 ether 00:11:22:33:44:55 CACHED
*/
static int parse_linux_line(const char *line, arp_entry_t *out) {
    if (!line || !out) return 0;
    /* look for ip at start */
    char ip[32] = {0}, mac[64] = {0};
    const char *p = line;
    if (sscanf(p, "%31s", ip) != 1) return 0;
    /* find "lladdr" (preferred) or "ether" */
    const char *ll = strstr(line, "lladdr");
    if (ll) {
        if (sscanf(ll, "lladdr %63s", mac) != 1) mac[0] = '\0';
    } else {
        const char *et = strstr(line, "ether");
        if (et) {
            if (sscanf(et, "ether %63s", mac) != 1) mac[0] = '\0';
        } else {
            return 0;
        }
    }
    if (mac[0] == '\0') return 0;
    strncpy(out->ip, ip, sizeof(out->ip)-1);
    strncpy(out->mac, mac, sizeof(out->mac)-1);
    return 1;
}
#endif

#ifdef __APPLE__
/* macOS arp -a lines:
? (192.168.1.10) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
*/
static int parse_macos_line(const char *line, arp_entry_t *out) {
    if (!line || !out) return 0;
    char ip[32] = {0}, mac[64] = {0};
    const char *p = strchr(line, '(');
    if (!p) return 0;
    ++p;
    if (sscanf(p, "%31[^)]", ip) != 1) return 0;
    const char *at = strstr(line, " at ");
    if (!at) return 0;
    at += 4;
    if (sscanf(at, "%63s", mac) != 1) return 0;
    /* sometimes mac is "(incomplete)" -> ignore */
    if (strstr(mac, "(incomplete)")) return 0;
    strncpy(out->ip, ip, sizeof(out->ip)-1);
    strncpy(out->mac, mac, sizeof(out->mac)-1);
    return 1;
}
#endif

#ifdef _WIN32
/* Windows arp -a sample:
Interface: 192.168.1.5 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
*/
static int parse_windows_line(const char *line, arp_entry_t *out) {
    if (!line || !out) return 0;
    /* line containing IP at column 1 or with whitespace */
    char ip[32] = {0}, mac[64] = {0};
    /* skip leading spaces */
    const char *p = line;
    while (*p == ' ' || *p == '\t') ++p;
    if (!isdigit((unsigned char)*p)) return 0;
    if (sscanf(p, "%31s %63s", ip, mac) < 2) return 0;
    /* mac in Windows uses hyphens; normalize to colons */
    for (char *q = mac; *q; ++q) if (*q == '-') *q = ':';
    strncpy(out->ip, ip, sizeof(out->ip)-1);
    strncpy(out->mac, mac, sizeof(out->mac)-1);
    return 1;
}
#endif

int get_arp_entries(arp_entry_t **entries_out) {
    if (!entries_out) return -1;
    FILE *fp = NULL;
    char *cmd = NULL;

#ifdef __linux__
    /* Try ip neigh first, fallback to arp -n */
    cmd = "ip neigh show";
    fp = popen(cmd, "r");
    if (!fp) {
        cmd = "arp -n";
        fp = popen(cmd, "r");
        if (!fp) return -1;
    }
#elif defined(__APPLE__)
    cmd = "arp -a";
    fp = popen(cmd, "r");
    if (!fp) return -1;
#elif defined(_WIN32)
    /* Use arp -a (Windows). Use _popen */
    cmd = "arp -a";
    fp = _popen(cmd, "r");
    if (!fp) return -1;
#else
    return -1;
#endif

    arp_entry_t *arr = NULL;
    size_t cap = 0, n = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        arp_entry_t e;
        memset(&e, 0, sizeof(e));
        int ok = 0;
#ifdef __linux__
        ok = parse_linux_line(line, &e);
#elif defined(__APPLE__)
        ok = parse_macos_line(line, &e);
#elif defined(_WIN32)
        ok = parse_windows_line(line, &e);
#endif
        if (ok) {
            if (n >= cap) {
                size_t newcap = (cap == 0) ? 16 : cap * 2;
                arp_entry_t *tmp = (arp_entry_t *)realloc(arr, newcap * sizeof(arp_entry_t));
                if (!tmp) {
                    free(arr);
#ifdef _WIN32
                    _pclose(fp);
#else
                    pclose(fp);
#endif
                    return -1;
                }
                arr = tmp;
                cap = newcap;
            }
            arr[n++] = e;
        }
    }

#ifdef _WIN32
    _pclose(fp);
#else
    pclose(fp);
#endif

    /* shrink */
    if (n == 0) {
        free(arr);
        arr = NULL;
    } else {
        arp_entry_t *tmp = (arp_entry_t *)realloc(arr, n * sizeof(arp_entry_t));
        if (tmp) arr = tmp;
    }
    *entries_out = arr;
    return (int)n;
}

/* -------------------- OUI loading & lookup -------------------- */

/* Normalize prefix: input like "28-6F-B9" or "286FB9" -> outputs uppercase "286FB9" into dest (len>=7) */
static void normalize_prefix(const char *in, char *dest) {
    int di = 0;
    for (const char *p = in; *p && di < 6; ++p) {
        if (*p == '-' || *p == ':' || *p == ' ') continue;
        dest[di++] = (char)toupper((unsigned char)*p);
    }
    dest[di] = '\0';
}

/* Load OUI file where lines like:
   28-6F-B9   (hex)        Nokia Shanghai Bell Co., Ltd.
   286FB9     (base 16)    Nokia Shanghai Bell Co., Ltd.
*/
int load_oui_db(const char *path, char ***prefixes_out, char ***vendors_out) {
    if (!path || !prefixes_out || !vendors_out) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    size_t cap = 0, n = 0;
    char **prefixes = NULL;
    char **vendors = NULL;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        /* attempt to find hyphenated prefix XX-XX-XX */
        char a[3], b[3], c[3];
        if (sscanf(line, " %2[0-9A-Fa-f]-%2[0-9A-Fa-f]-%2[0-9A-Fa-f]", a, b, c) == 3) {
            char pref_raw[8];
            snprintf(pref_raw, sizeof(pref_raw), "%s%s%s", a, b, c);
            char pref[7];
            normalize_prefix(pref_raw, pref);

            /* Now extract vendor string from the rest of the line.
               Strategy: look for "(hex)" or "(base 16)" then vendor name after that.
               If not found, try to take the rest of the line after the three-octet token.
            */
            char *vendor = NULL;
            char *phex = strstr(line, "(hex)");
            if (!phex) phex = strstr(line, "(base 16)");
            if (phex) {
                phex += strlen("(hex)"); /* if matched (hex) else points after (base 16) but ok */
                /* if this actually matched base 16, move past it too */
                if (strncmp(phex - strlen("(hex)"), "(base 16)", 10) == 0) {
                    /* if it matched base 16 the pointer arithmetic above is off; better find the token end */
                    phex = strstr(line, "(base 16)");
                    phex += strlen("(base 16)");
                }
                while (*phex && isspace((unsigned char)*phex)) phex++;
                vendor = phex;
            } else {
                /* fallback: find third token end */
                char *p = line;
                int tokens = 0;
                while (*p && tokens < 3) {
                    if (isspace((unsigned char)*p)) {
                        while (*p && isspace((unsigned char)*p)) p++;
                        tokens++;
                    } else p++;
                }
                while (*p && isspace((unsigned char)*p)) p++;
                if (*p) vendor = p;
            }

            if (vendor) {
                /* trim newline and trailing spaces */
                char *vend_trim = vendor;
                while (*vend_trim && (*vend_trim == '\t' || *vend_trim == ' ')) vend_trim++;
                char *end = vend_trim + strlen(vend_trim);
                while (end > vend_trim && isspace((unsigned char)*(end-1))) { end--; }
                size_t vlen = (size_t)(end - vend_trim);
                if (vlen > 0) {
                    char *vcopy = (char *)malloc(vlen + 1);
                    if (!vcopy) { fclose(f); return -1; }
                    memcpy(vcopy, vend_trim, vlen);
                    vcopy[vlen] = '\0';

                    /* store */
                    if (n >= cap) {
                        size_t newcap = (cap == 0) ? 256 : cap * 2;
                        char **ptmp = (char **)realloc(prefixes, newcap * sizeof(char*));
                        char **vtmp = (char **)realloc(vendors, newcap * sizeof(char*));
                        if (!ptmp || !vtmp) {
                            free(vcopy);
                            fclose(f);
                            return -1;
                        }
                        prefixes = ptmp;
                        vendors = vtmp;
                        cap = newcap;
                    }
                    prefixes[n] = (char *)malloc(7);
                    if (!prefixes[n]) { free(vcopy); fclose(f); return -1; }
                    strcpy(prefixes[n], pref);
                    vendors[n] = vcopy;
                    n++;
                }
            }
        }
    }

    fclose(f);
    if (n == 0) {
        free(prefixes);
        free(vendors);
        *prefixes_out = NULL;
        *vendors_out = NULL;
        return 0;
    }
    /* shrink to fit */
    prefixes = (char **)realloc(prefixes, n * sizeof(char*));
    vendors = (char **)realloc(vendors, n * sizeof(char*));
    *prefixes_out = prefixes;
    *vendors_out = vendors;
    return (int)n;
}

/* Given a MAC like "00:11:22:33:44:55" or "00-11-22-33-44-55", returns vendor string pointer
 * from loaded arrays, or NULL if not found.
 */
/* Helper: convert MAC string to 6-hex-digit uppercase prefix
 * Accepts formats like "0:11:22:33:44:55", "00:11:22:33:44:55", "00-11-22-33-44-55" etc.
 * Writes 6 chars + trailing NUL into `out` (size >= 7). Returns 0 on success, -1 on error.
 */
static int mac_to_oui_prefix(const char *mac, char *out) {
    if (!mac || !out) return -1;
    int octet = 0;
    const char *p = mac;
    char token[16];
    while (*p && octet < 3) {
        /* read up to next separator into token */
        int ti = 0;
        while (*p && *p != ':' && *p != '-' && *p != '.' && !isspace((unsigned char)*p) && ti < (int)sizeof(token)-1) {
            token[ti++] = *p++;
        }
        token[ti] = '\0';
        /* skip separators */
        while (*p && (*p == ':' || *p == '-' || *p == '.' || isspace((unsigned char)*p))) ++p;

        if (ti == 0) return -1;
        /* parse hex value */
        char *endptr = NULL;
        long v = strtol(token, &endptr, 16);
        if (endptr == token || v < 0 || v > 0xFF) return -1;
        /* write two uppercase hex digits */
        unsigned uv = (unsigned)v;
        out[octet*2 + 0] = "0123456789ABCDEF"[(uv >> 4) & 0xF];
        out[octet*2 + 1] = "0123456789ABCDEF"[uv & 0xF];
        octet++;
    }
    if (octet < 3) return -1;
    out[6] = '\0';
    return 0;
}

const char *lookup_oui_vendor(const char *mac, char * const *prefixes, char * const *vendors, int count) {
    if (!mac || !prefixes || !vendors || count <= 0) return NULL;
    char norm[7] = {0};
    if (mac_to_oui_prefix(mac, norm) != 0) return NULL;
    /* linear search is fine for moderate OUI list size */
    for (int i = 0; i < count; ++i) {
        if (strcmp(prefixes[i], norm) == 0) return vendors[i];
    }
    return NULL;
}
