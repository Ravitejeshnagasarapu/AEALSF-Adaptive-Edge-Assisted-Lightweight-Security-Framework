#include <stdint.h>
#include <string.h>

typedef unsigned __int128 uint128_t;

typedef struct {
    uint64_t d[4];
} fe256;

static const fe256 SECP_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};

static inline int fe_is_zero(const fe256 *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

static inline int fe_gte_p(const fe256 *a) {
    if (a->d[3] < SECP_P.d[3]) return 0;
    if (a->d[2] < SECP_P.d[2]) return 0;
    if (a->d[1] < SECP_P.d[1]) return 0;
    return a->d[0] >= SECP_P.d[0];
}

static inline void fe_add(fe256 *r, const fe256 *a, const fe256 *b) {
    uint128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (uint128_t)a->d[i] + b->d[i];
        r->d[i] = (uint64_t)c;
        c >>= 64;
    }
    if (c || fe_gte_p(r)) {
        uint128_t acc = (uint128_t)r->d[0] + 0x1000003D1ULL;
        r->d[0] = (uint64_t)acc; acc >>= 64;
        for (int i = 1; i < 4; i++) {
            acc += r->d[i];
            r->d[i] = (uint64_t)acc; acc >>= 64;
        }
    }
}

static inline void fe_sub(fe256 *r, const fe256 *a, const fe256 *b) {
    uint128_t borrow = 0;
    fe256 tmp;
    for (int i = 0; i < 4; i++) {
        uint128_t ai = a->d[i];
        uint128_t bi = (uint128_t)b->d[i] + borrow;
        if (ai >= bi) {
            tmp.d[i] = (uint64_t)(ai - bi);
            borrow = 0;
        } else {
            tmp.d[i] = (uint64_t)(((uint128_t)1 << 64) + ai - bi);
            borrow = 1;
        }
    }
    if (borrow) {
        uint128_t b2 = 0x1000003D1ULL;
        for (int i = 0; i < 4; i++) {
            uint128_t ti = tmp.d[i];
            if (ti >= b2) {
                tmp.d[i] = (uint64_t)(ti - b2);
                b2 = 0;
            } else {
                tmp.d[i] = (uint64_t)(((uint128_t)1 << 64) + ti - b2);
                b2 = 1;
            }
        }
    }
    *r = tmp;
}

static inline void fe_mul(fe256 *r, const fe256 *a, const fe256 *b) {
    uint64_t t[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)a->d[i] * b->d[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        t[i + 4] = (uint64_t)carry;
    }
    uint64_t u[5] = {0};
    uint128_t c = 0;
    const uint64_t K = 0x1000003D1ULL;
    for (int i = 0; i < 4; i++) {
        uint128_t prod = (uint128_t)t[i + 4] * K + t[i] + c;
        u[i] = (uint64_t)prod;
        c = prod >> 64;
    }
    u[4] = (uint64_t)c;
    uint128_t c2 = (uint128_t)u[4] * K + u[0];
    r->d[0] = (uint64_t)c2; c2 >>= 64;
    for (int i = 1; i < 4; i++) {
        c2 += u[i];
        r->d[i] = (uint64_t)c2; c2 >>= 64;
    }
    if (c2 || fe_gte_p(r)) {
        uint128_t acc = (uint128_t)r->d[0] + K;
        r->d[0] = (uint64_t)acc; acc >>= 64;
        for (int i = 1; i < 4; i++) {
            acc += r->d[i];
            r->d[i] = (uint64_t)acc; acc >>= 64;
        }
    }
}

static inline void fe_sqr(fe256 *r, const fe256 *a) {
    fe_mul(r, a, a);
}

static void fe_inv(fe256 *r, const fe256 *a) {
    static const uint64_t PM2[4] = {
        0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
    };
    fe256 tab[16];
    tab[0] = (fe256){{1, 0, 0, 0}};
    tab[1] = *a;
    for (int v = 2; v < 16; v++) {
        fe_mul(&tab[v], &tab[v - 1], a);
    }
    fe256 res = {{1, 0, 0, 0}};
    for (int limb = 3; limb >= 0; limb--) {
        uint64_t w = PM2[limb];
        for (int nib = 15; nib >= 0; nib--) {
            if (!(limb == 3 && nib == 15)) {
                fe_sqr(&res, &res);
                fe_sqr(&res, &res);
                fe_sqr(&res, &res);
                fe_sqr(&res, &res);
            }
            int idx = (int)((w >> (nib * 4)) & 0xFULL);
            if (idx) fe_mul(&res, &res, &tab[idx]);
        }
    }
    *r = res;
}

typedef struct {
    fe256 x, y, z;
} jac_pt;

static void jac_double(jac_pt *r, const jac_pt *p) {
    if (fe_is_zero(&p->z) || fe_is_zero(&p->y)) {
        memset(r, 0, sizeof(*r));
        r->y.d[0] = 1;
        return;
    }
    fe256 ysq, s, m, x3, y3, z3, t1, t2;
    fe_sqr(&ysq, &p->y);
    fe_mul(&s, &p->x, &ysq);
    fe_add(&s, &s, &s);
    fe_add(&s, &s, &s);
    fe_sqr(&t1, &p->x);
    fe_add(&m, &t1, &t1);
    fe_add(&m, &m, &t1);
    fe_sqr(&x3, &m);
    fe_sub(&x3, &x3, &s);
    fe_sub(&x3, &x3, &s);
    fe_sub(&t1, &s, &x3);
    fe_mul(&y3, &m, &t1);
    fe_sqr(&t2, &ysq);
    fe_add(&t2, &t2, &t2);
    fe_add(&t2, &t2, &t2);
    fe_add(&t2, &t2, &t2);
    fe_sub(&y3, &y3, &t2);
    fe_mul(&z3, &p->y, &p->z);
    fe_add(&z3, &z3, &z3);
    r->x = x3; r->y = y3; r->z = z3;
}

static void jac_add(jac_pt *r, const jac_pt *p1, const jac_pt *p2) {
    if (fe_is_zero(&p1->z)) { *r = *p2; return; }
    if (fe_is_zero(&p2->z)) { *r = *p1; return; }
    fe256 z1sq, z2sq, u1, u2, s1, s2, h, rr, hsq, hcu, u1hsq, x3, y3, z3, t;
    fe_sqr(&z1sq, &p1->z);
    fe_sqr(&z2sq, &p2->z);
    fe_mul(&u1, &p1->x, &z2sq);
    fe_mul(&u2, &p2->x, &z1sq);
    fe_mul(&t, &z2sq, &p2->z);
    fe_mul(&s1, &p1->y, &t);
    fe_mul(&t, &z1sq, &p1->z);
    fe_mul(&s2, &p2->y, &t);
    if (memcmp(&u1, &u2, sizeof(fe256)) == 0) {
        if (memcmp(&s1, &s2, sizeof(fe256)) != 0) {
            memset(r, 0, sizeof(*r));
            r->y.d[0] = 1;
            return;
        }
        jac_double(r, p1);
        return;
    }
    fe_sub(&h, &u2, &u1);
    fe_sub(&rr, &s2, &s1);
    fe_sqr(&hsq, &h);
    fe_mul(&hcu, &h, &hsq);
    fe_mul(&u1hsq, &u1, &hsq);
    fe_sqr(&x3, &rr);
    fe_sub(&x3, &x3, &hcu);
    fe_sub(&x3, &x3, &u1hsq);
    fe_sub(&x3, &x3, &u1hsq);
    fe_sub(&t, &u1hsq, &x3);
    fe_mul(&y3, &rr, &t);
    fe_mul(&t, &s1, &hcu);
    fe_sub(&y3, &y3, &t);
    fe_mul(&t, &p1->z, &p2->z);
    fe_mul(&z3, &h, &t);
    r->x = x3; r->y = y3; r->z = z3;
}

static jac_pt G_TABLE[32][256];
static int g_table_ready = 0;

typedef struct {
    int valid;
    uint64_t px[4];
    uint64_t py[4];
    jac_pt win[8][16];
} pk_comb_entry;

static pk_comb_entry PK_CACHE[8192];

void init_g_table(void) {
    if (g_table_ready) return;
    memset(PK_CACHE, 0, sizeof(PK_CACHE));
    jac_pt base;
    base.x = (fe256){{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}};
    base.y = (fe256){{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}};
    base.z = (fe256){{1, 0, 0, 0}};
    for (int i = 0; i < 32; i++) {
        memset(&G_TABLE[i][0], 0, sizeof(jac_pt));
        G_TABLE[i][0].y.d[0] = 1;
        jac_pt acc = G_TABLE[i][0];
        for (int b = 1; b < 256; b++) {
            jac_add(&acc, &acc, &base);
            G_TABLE[i][b] = acc;
        }
        for (int d = 0; d < 8; d++) jac_double(&base, &base);
    }
    g_table_ready = 1;
}

static void mul_g_jac(jac_pt *acc, const uint64_t k[4]) {
    if (!g_table_ready) init_g_table();
    memset(acc, 0, sizeof(*acc));
    acc->y.d[0] = 1;
    const uint8_t *kb = (const uint8_t *)k;
    for (int i = 0; i < 32; i++) {
        uint8_t b = kb[i];
        if (b) jac_add(acc, acc, &G_TABLE[i][b]);
    }
}

static void mul_p_jac(jac_pt *acc, const uint64_t k[4], const uint64_t px[4], const uint64_t py[4]) {
    if (k[1] == 0 && k[2] == 0 && k[3] == 0 && k[0] < 65536ULL) {
        memset(acc, 0, sizeof(*acc));
        acc->y.d[0] = 1;
        jac_pt base;
        memcpy(base.x.d, px, 32);
        memcpy(base.y.d, py, 32);
        base.z = (fe256){{1, 0, 0, 0}};
        uint64_t kv = k[0];
        while (kv > 0) {
            if (kv & 1ULL) jac_add(acc, acc, &base);
            jac_double(&base, &base);
            kv >>= 1;
        }
        return;
    }
    uint32_t base_idx = (uint32_t)((px[0] ^ (px[1] >> 13) ^ (py[0] >> 7)) & 8191ULL);
    pk_comb_entry *ent = &PK_CACHE[base_idx];
    for (uint32_t probe = 0; probe < 8; probe++) {
        pk_comb_entry *cand = &PK_CACHE[(base_idx + probe) & 8191ULL];
        if (!cand->valid || (memcmp(cand->px, px, 32) == 0 && memcmp(cand->py, py, 32) == 0)) {
            ent = cand;
            break;
        }
    }
    if (!ent->valid || memcmp(ent->px, px, 32) != 0 || memcmp(ent->py, py, 32) != 0) {
        ent->valid = 1;
        memcpy(ent->px, px, 32);
        memcpy(ent->py, py, 32);
        jac_pt base;
        memcpy(base.x.d, px, 32);
        memcpy(base.y.d, py, 32);
        base.z = (fe256){{1, 0, 0, 0}};
        for (int j = 0; j < 8; j++) {
            memset(&ent->win[j][0], 0, sizeof(jac_pt));
            ent->win[j][0].y.d[0] = 1;
            ent->win[j][1] = base;
            for (int v = 2; v < 16; v++) {
                jac_add(&ent->win[j][v], &ent->win[j][v - 1], &base);
            }
            if (j < 7) {
                for (int d = 0; d < 32; d++) jac_double(&base, &base);
            }
        }
    }
    memset(acc, 0, sizeof(*acc));
    acc->y.d[0] = 1;
    const uint32_t *k32 = (const uint32_t *)k;
    for (int nib = 7; nib >= 0; nib--) {
        if (nib < 7) {
            for (int d = 0; d < 4; d++) jac_double(acc, acc);
        }
        int shift = nib * 4;
        for (int j = 0; j < 8; j++) {
            int v = (k32[j] >> shift) & 0xF;
            if (v) jac_add(acc, acc, &ent->win[j][v]);
        }
    }
}

int c_scalar_mul(const uint64_t k[4], const uint64_t px[4], const uint64_t py[4], int is_g, uint64_t rx[4], uint64_t ry[4]) {
    jac_pt acc;
    if (is_g) {
        mul_g_jac(&acc, k);
    } else {
        mul_p_jac(&acc, k, px, py);
    }
    if (fe_is_zero(&acc.z)) return 0;
    fe256 zinv, z2, z3, ax, ay;
    fe_inv(&zinv, &acc.z);
    fe_sqr(&z2, &zinv);
    fe_mul(&z3, &z2, &zinv);
    fe_mul(&ax, &acc.x, &z2);
    fe_mul(&ay, &acc.y, &z3);
    memcpy(rx, ax.d, 32);
    memcpy(ry, ay.d, 32);
    return 1;
}

int c_schnorr_verify_eq(
    const uint64_t z[4],
    const uint64_t c[4],
    const uint64_t rx[4],
    const uint64_t ry[4],
    const uint64_t pkx[4],
    const uint64_t pky[4]
) {

    jac_pt lhs, c_pk, r_pt, rhs;
    mul_g_jac(&lhs, z);
    mul_p_jac(&c_pk, c, pkx, pky);
    memcpy(r_pt.x.d, rx, 32);
    memcpy(r_pt.y.d, ry, 32);
    r_pt.z = (fe256){{1, 0, 0, 0}};
    jac_add(&rhs, &r_pt, &c_pk);
    if (fe_is_zero(&lhs.z) || fe_is_zero(&rhs.z)) return 0;

    fe256 z1sq, z2sq, z1cu, z2cu, x1z2, x2z1, y1z2, y2z1;
    fe_sqr(&z1sq, &lhs.z);
    fe_sqr(&z2sq, &rhs.z);
    fe_mul(&x1z2, &lhs.x, &z2sq);
    fe_mul(&x2z1, &rhs.x, &z1sq);
    if (memcmp(&x1z2, &x2z1, sizeof(fe256)) != 0) return 0;

    fe_mul(&z1cu, &z1sq, &lhs.z);
    fe_mul(&z2cu, &z2sq, &rhs.z);
    fe_mul(&y1z2, &lhs.y, &z2cu);
    fe_mul(&y2z1, &rhs.y, &z1cu);
    return memcmp(&y1z2, &y2z1, sizeof(fe256)) == 0 ? 1 : 0;
}

int c_ec_add(const uint64_t x1[4], const uint64_t y1[4], const uint64_t x2[4], const uint64_t y2[4], uint64_t rx[4], uint64_t ry[4]) {
    jac_pt p1, p2, r;
    memcpy(p1.x.d, x1, 32);
    memcpy(p1.y.d, y1, 32);
    p1.z = (fe256){{1, 0, 0, 0}};
    memcpy(p2.x.d, x2, 32);
    memcpy(p2.y.d, y2, 32);
    p2.z = (fe256){{1, 0, 0, 0}};
    jac_add(&r, &p1, &p2);
    if (fe_is_zero(&r.z)) return 0;
    fe256 zinv, z2, z3, ax, ay;
    fe_inv(&zinv, &r.z);
    fe_sqr(&z2, &zinv);
    fe_mul(&z3, &z2, &zinv);
    fe_mul(&ax, &r.x, &z2);
    fe_mul(&ay, &r.y, &z3);
    memcpy(rx, ax.d, 32);
    memcpy(ry, ay.d, 32);
    return 1;
}
