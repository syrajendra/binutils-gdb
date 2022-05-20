#ifndef _MACHINE_TARGET_H_
#define _MACHINE_TARGET_H_ 1

typedef uint64_t	aarch64_physaddr_t;
typedef uint64_t	aarch64_pte_t;

#define	AARCH64_PAGE_SHIFT	12
#define	AARCH64_PAGE_SIZE	(1 << AARCH64_PAGE_SHIFT)
#define	AARCH64_PAGE_MASK	(AARCH64_PAGE_SIZE - 1)
#define	round_page(x)	((((unsigned long)(x)) + AARCH64_PAGE_MASK) & ~(AARCH64_PAGE_MASK))

/* Source: arm64/include/pte.h */
#define	AARCH64_ATTR_MASK	0xfff0000000000fff
#define	AARCH64_ATTR_UXN	(1ULL << 54)
#define	AARCH64_ATTR_PXN	(1ULL << 53)
#define	AARCH64_ATTR_XN		(AARCH64_ATTR_PXN | AARCH64_ATTR_UXN)
#define	AARCH64_ATTR_AP(x)	((x) << 6)
#define	AARCH64_ATTR_AP_RO	(1 << 1)

#define	AARCH64_ATTR_DESCR_MASK	3

#define	AARCH64_L3_SHIFT	12
#define	AARCH64_L3_PAGE		0x3

/* from machine/minidump.h */
#define MINIDUMP_MAGIC       "minidump FreeBSD/arm64"
#define MINIDUMP_VERSION     1

struct minidumphdr {
    char magic[24];
    uint32_t version;
    uint32_t msgbufsize;
    uint32_t bitmapsize;
    uint32_t pmapsize;
    uint64_t kernbase;
    uint64_t dmapphys;
    uint64_t dmapbase;
    uint64_t dmapend;
};

#endif
