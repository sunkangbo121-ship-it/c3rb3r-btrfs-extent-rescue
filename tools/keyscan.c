// Scan a LiME RAM image for 32-byte AES-256 keys that unwrap a C3RB3R footer record.
//
// Footer record = AES-256-CBC(master_key, master_iv) of key32 | nonce8 | nonce8.
// The third ciphertext block decrypts (independent of the IV) to nonce8|nonce8,
// so every candidate key can be tested against the footer alone.
//
// usage: keyscan RAM.lime FOOTERS.bin [threads]
//   FOOTERS.bin = N concatenated 48-byte footer records (footer[0:48]).
// Prints: offset, physical address, candidate key hex, footer index, and the 16
// bytes in front of the key (expected IV location for the iv16+key32 layout).
// Key material is printed in hex on purpose: this runs on the owner's analysis host.
#include <CommonCrypto/CommonCryptor.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MIN_DISTINCT 22

typedef struct { uint64_t file_off, paddr, len; } seg_t;

static const uint8_t *img;
static seg_t segs[64];
static int nsegs;
static uint8_t (*footers)[48];
static int nfooters;
static atomic_ullong tested, scanned;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct { uint64_t start, end; } job_t;  // file offsets, window starts in [start,end)

static void test_key(const uint8_t *key, uint64_t off) {
    CCCryptorRef c;
    if (CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, key, 32, NULL, &c) != kCCSuccess)
        return;
    for (int f = 0; f < nfooters; f++) {
        uint8_t p[16];
        size_t moved;
        CCCryptorUpdate(c, footers[f] + 32, 16, p, 16, &moved);
        for (int i = 0; i < 16; i++) p[i] ^= footers[f][16 + i];
        if (memcmp(p, p + 8, 8) == 0) {
            uint64_t paddr = 0;
            for (int s = 0; s < nsegs; s++)
                if (off >= segs[s].file_off && off < segs[s].file_off + segs[s].len)
                    paddr = segs[s].paddr + (off - segs[s].file_off);
            pthread_mutex_lock(&out_lock);
            printf("HIT footer=%d off=%llu paddr=%#llx key=", f, (unsigned long long)off,
                   (unsigned long long)paddr);
            for (int i = 0; i < 32; i++) printf("%02x", key[i]);
            printf(" prev16=");
            for (int i = -16; i < 0; i++) printf("%02x", off >= 16 ? key[i] : 0);
            printf(" nonce=");
            for (int i = 0; i < 8; i++) printf("%02x", p[i]);
            printf("\n");
            fflush(stdout);
            pthread_mutex_unlock(&out_lock);
        }
    }
    CCCryptorRelease(c);
}

static void *worker(void *arg) {
    job_t *j = arg;
    uint16_t hist[256];
    memset(hist, 0, sizeof hist);
    int distinct = 0;
    const uint8_t *b = img;
    uint64_t start = j->start;
    for (int i = 0; i < 32; i++)
        if (hist[b[start + i]]++ == 0) distinct++;
    uint64_t local = 0;
    for (uint64_t o = start; o < j->end; o++) {
        if (distinct >= MIN_DISTINCT) {
            test_key(b + o, o);
            local++;
        }
        // slide window [o, o+32) -> [o+1, o+33)
        if (--hist[b[o]] == 0) distinct--;
        if (hist[b[o + 32]]++ == 0) distinct++;
        if ((o & 0xFFFFFF) == 0) {
            atomic_fetch_add(&tested, local);
            local = 0;
            atomic_fetch_add(&scanned, 0x1000000);
        }
    }
    atomic_fetch_add(&tested, local);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s RAM.lime FOOTERS.bin [threads]\n", argv[0]);
        return 2;
    }
    int nthreads = argc > 3 ? atoi(argv[3]) : 8;
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) { perror("ram"); return 1; }
    img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (img == MAP_FAILED) { perror("mmap"); return 1; }

    FILE *ff = fopen(argv[2], "rb");
    if (!ff) { perror("footers"); return 1; }
    footers = malloc(48 * 1024);
    nfooters = (int)fread(footers, 48, 1024, ff);
    fclose(ff);
    if (nfooters < 1) { fprintf(stderr, "no footers\n"); return 1; }

    uint64_t pos = 0;
    while (pos + 32 <= (uint64_t)st.st_size && nsegs < 64) {
        uint32_t magic, ver;
        uint64_t s, e;
        memcpy(&magic, img + pos, 4);
        memcpy(&ver, img + pos + 4, 4);
        memcpy(&s, img + pos + 8, 8);
        memcpy(&e, img + pos + 16, 8);
        if (magic != 0x4C694D45) { fprintf(stderr, "bad LiME header at %llu\n", (unsigned long long)pos); return 1; }
        uint64_t len = e - s + 1;
        if (pos + 32 + len > (uint64_t)st.st_size) len = st.st_size - pos - 32;  // truncated image
        segs[nsegs++] = (seg_t){pos + 32, s, len};
        pos += 32 + len;
    }
    fprintf(stderr, "%d segments, %d footers, %d threads\n", nsegs, nfooters, nthreads);

    // split every segment into jobs
    job_t *jobs = calloc(4096, sizeof *jobs);
    int njobs = 0;
    for (int s = 0; s < nsegs; s++) {
        if (segs[s].len < 64) continue;
        uint64_t a = segs[s].file_off, end = a + segs[s].len - 32;
        uint64_t step = 256ull << 20;
        for (; a < end; a += step)
            jobs[njobs++] = (job_t){a, a + step < end ? a + step : end};
    }
    int next = 0;
    pthread_t th[64];
    while (next < njobs) {
        int n = 0;
        for (; n < nthreads && next < njobs; n++, next++)
            pthread_create(&th[n], NULL, worker, &jobs[next]);
        for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
        fprintf(stderr, "jobs %d/%d  scanned~%.2f GiB  key tests %llu\n", next, njobs,
                atomic_load(&scanned) / 1073741824.0, (unsigned long long)atomic_load(&tested));
    }
    fprintf(stderr, "done\n");
    return 0;
}
