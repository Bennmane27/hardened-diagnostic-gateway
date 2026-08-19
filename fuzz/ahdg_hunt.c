/*
 * ahdg_hunt.c
 *
 * Moteur adversarial coverage-guided pour AHDG, avec modes de campagne et
 * chasseur de graines (Seed Hunter).
 *
 * Idee directrice : le bon critere n'est pas "faire chauffer le CPU" mais
 * MAXIMISER LA COUVERTURE D'ETATS RARES. Un seed qui tourne 20 s dans les
 * memes 8 etats n'a aucun interet ; un seed qui met 400 ms mais atteint un
 * nouvel etat, une nouvelle transition, une nouvelle condition cross-layer,
 * est precieux.
 *
 * L'outil pilote le VRAI pipeline isotp_rx + uds (code de production) et
 * mesure, apres chaque action : couverture d'ETATS (empreinte session x
 * securite x ISO-TP x timing), de TRANSITIONS, d'ISSUES (SID positifs,
 * NRC), profondeur atteinte, et etats RARES (vus <= RARE_THRESHOLD fois).
 *
 * Modes :
 *   normal  [seed] [budget]       1M sequences, profondeur <= 8, aleatoire
 *   stress  [seed] [budget]       100M sequences, profondeur <= 64
 *   deep    [seed] [max_iters]    coverage-guided, profondeur <= 256, mutations
 *   extreme [seed] [max_seconds]  jusqu'a : contre-exemple | plateau | delai
 *   hunt    [n_seeds] [attack]    scanne n_seeds, classe par NOUVEAUTE, annonce
 *                                 le seed le plus dur, puis l'attaque (deep)
 *
 * Deterministe. Build : make hunt
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"
#include "invariants.h"

typedef struct { uint32_t s; } rng_t;
static uint32_t rr(rng_t *r)
{
    r->s ^= r->s << 13; r->s ^= r->s >> 17; r->s ^= r->s << 5;
    return r->s;
}

static double now_seconds(void)
{
    struct timespec t;
    (void)clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---- Modele ECU : le vrai pipeline transport + application -------- */

typedef struct
{
    isotp_rx_context_t rx;
    uds_context_t      uds;
    ecu_data_t         data;
    uint32_t           clock;
} model_t;

static void model_init(model_t *m)
{
    isotp_rx_init(&m->rx);
    ecu_data_init(&m->data);
    uds_init(&m->uds);
    uds_set_did_provider(&m->uds, ecu_data_read_did, &m->data);
    uds_set_dtc_provider(&m->uds, ecu_data_read_dtc, ecu_data_clear_dtc);
    uds_set_reset_handler(&m->uds, ecu_data_reset);
    m->clock = 1000u;
}

typedef struct { uds_session_t se; uint8_t sl, sp, fa, lo; } snap_t;
static snap_t snap(const uds_context_t *c)
{
    snap_t s; s.se=c->session; s.sl=c->security_level; s.sp=c->seed_pending;
    s.fa=c->failed_attempts; s.lo=c->locked_out; return s;
}

static int check_uds(const snap_t *pre, const uds_context_t *p,
                     const uint8_t *resp, uint16_t rl)
{
    int pr=(rl>=1u)&&(resp[0]==0x51u);
    int pk=(rl>=2u)&&(resp[0]==0x67u)&&(resp[1]==0x02u);
    if (pr && (pre->sl==UDS_SECURITY_LOCKED)) return HDG_INV_SEC_NO_UNAUTH_EFFECT;
    if (pk && (pre->sp==0u)) return HDG_INV_SEC_SEED_KEY_BINDING;
    if (pr && (p->security_level!=UDS_SECURITY_LOCKED)) return HDG_INV_SEC_RELOCK_ON_RESET;
    if (pr && (p->seed_pending!=0u)) return HDG_INV_XL_NO_AUTHORITY_CARRYOVER;
    if ((p->session==UDS_SESSION_DEFAULT)&&(p->security_level!=UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_RELOCK_ON_DEFAULT;
    return -1;
}

static int feed(model_t *m, const uint8_t *frame, uint8_t len, int *outcome)
{
    isotp_rx_result_t rxo;
    *outcome = 0;
    m->clock += 1u;
    (void)isotp_rx_process(&m->rx, frame, len, m->clock, &rxo);

    if (m->rx.received_length > m->rx.expected_length)
        return HDG_INV_TP_LENGTH_HONESTY;

    if (rxo.event == ISOTP_RX_EVENT_MESSAGE_READY)
    {
        uint8_t resp[UDS_MAX_RESPONSE_SIZE]; uint16_t rl=0u;
        snap_t pre = snap(&m->uds);
        if (rxo.message_len > ISOTP_MAX_PAYLOAD_SIZE)
            return HDG_INV_XL_TRANSPORT_CANNOT_FORGE_AUTHORITY;
        (void)uds_handle_request(&m->uds, rxo.message, rxo.message_len,
                                 m->clock, resp, (uint16_t)sizeof(resp), &rl);
        if (rl >= 1u)
        {
            if (resp[0]==0x7Fu && rl>=3u) *outcome = 0x100 | resp[2];
            else *outcome = resp[0];
        }
        return check_uds(&pre, &m->uds, resp, rl);
    }
    return -1;
}

static int golden_ok(model_t *m)
{
    uint8_t sf1[8]={0x02,0x10,0x03,0,0,0,0,0};
    uint8_t sf2[8]={0x03,0x22,0xF1,0x89,0,0,0,0};
    isotp_rx_result_t rxo; uint8_t resp[UDS_MAX_RESPONSE_SIZE]; uint16_t rl;
    int o1=0,o2=0;
    m->clock+=1u;
    (void)isotp_rx_process(&m->rx, sf1, 8u, m->clock, &rxo);
    if (rxo.event==ISOTP_RX_EVENT_MESSAGE_READY){ rl=0u;
        (void)uds_handle_request(&m->uds,rxo.message,rxo.message_len,m->clock,
                                 resp,(uint16_t)sizeof(resp),&rl);
        o1=(rl>=1u)&&(resp[0]==0x50u); }
    m->clock+=1u;
    (void)isotp_rx_process(&m->rx, sf2, 8u, m->clock, &rxo);
    if (rxo.event==ISOTP_RX_EVENT_MESSAGE_READY){ rl=0u;
        (void)uds_handle_request(&m->uds,rxo.message,rxo.message_len,m->clock,
                                 resp,(uint16_t)sizeof(resp),&rl);
        o2=(rl>=1u)&&(resp[0]==0x62u); }
    return (o1&&o2)?1:0;
}

/* ---- Alphabet (mutations timing/ISO-TP/UDS/etat comprises) -------- */

enum {
    A_SESS_EXT=0, A_SESS_DEF, A_SEED, A_KEY_OK, A_KEY_BAD, A_RESET,
    A_READ, A_PRESENT, A_CLEAR, A_FF, A_CF_OK, A_CF_BAD, A_GARBAGE,
    A_FC, A_NCR, A_TICK, A_S3, A_LOCKOUT, A_INTERLEAVE, A_COUNT
};

static int apply_act(model_t *m, int a, rng_t *rng, int *outcome)
{
    uint8_t f[8]; memset(f,0,sizeof(f)); *outcome=0;
    switch (a) {
    case A_SESS_EXT: f[0]=0x02;f[1]=0x10;f[2]=0x03; return feed(m,f,8u,outcome);
    case A_SESS_DEF: f[0]=0x02;f[1]=0x10;f[2]=0x01; return feed(m,f,8u,outcome);
    case A_SEED:     f[0]=0x02;f[1]=0x27;f[2]=0x01; return feed(m,f,8u,outcome);
    case A_KEY_OK: { uint32_t k=uds_demo_key_from_seed(m->uds.current_seed);
        f[0]=0x05;f[1]=0x27;f[2]=0x02;f[3]=(uint8_t)(k>>24);f[4]=(uint8_t)(k>>16);
        f[5]=(uint8_t)(k>>8);f[6]=(uint8_t)k; return feed(m,f,8u,outcome); }
    case A_KEY_BAD: { uint8_t g[8]={0x05,0x27,0x02,0xDE,0xAD,0xBE,0xEF,0}; return feed(m,g,8u,outcome); }
    case A_RESET:   f[0]=0x02;f[1]=0x11;f[2]=0x01; return feed(m,f,8u,outcome);
    case A_READ:    f[0]=0x03;f[1]=0x22;f[2]=0xF1;f[3]=0x90; return feed(m,f,8u,outcome);
    case A_PRESENT: f[0]=0x02;f[1]=0x3E;f[2]=0x00; return feed(m,f,8u,outcome);
    case A_CLEAR:   f[0]=0x04;f[1]=0x14;f[2]=0xFF;f[3]=0xFF;f[4]=0xFF; return feed(m,f,8u,outcome);
    case A_FF: { uint8_t g[8]={0x10,0x14,0x22,0xF1,0x90,0xAA,0xBB,0xCC}; return feed(m,g,8u,outcome); }
    case A_CF_OK: { uint8_t sn=m->rx.next_sequence_number;
        f[0]=(uint8_t)(0x20u|(sn&0x0Fu));f[1]=1;f[2]=2;f[3]=3;f[4]=4;f[5]=5;f[6]=6;f[7]=7;
        return feed(m,f,8u,outcome); }
    case A_CF_BAD: { f[0]=0x2F;f[1]=1;f[2]=2;f[3]=3;f[4]=4;f[5]=5;f[6]=6;f[7]=7; return feed(m,f,8u,outcome); }
    case A_GARBAGE: { f[0]=(uint8_t)(((rr(rng)%12u)+4u)<<4); return feed(m,f,(uint8_t)((rr(rng)%8u)+1u),outcome); }
    case A_FC: { uint8_t g[8]={0x30,0,0,0,0,0,0,0}; return feed(m,g,8u,outcome); }
    case A_NCR: { isotp_rx_result_t rxo; m->clock+=(ISOTP_N_CR_TIMEOUT_MS+10u);
        (void)isotp_rx_poll_timeout(&m->rx,m->clock,&rxo); return -1; }
    case A_TICK: { m->clock+=5u; uds_poll(&m->uds,m->clock); return -1; }
    case A_S3: { m->clock+=(UDS_S3_SERVER_TIMEOUT_MS+10u); uds_poll(&m->uds,m->clock); return -1; }
    case A_LOCKOUT: { m->clock+=(UDS_SECURITY_LOCKOUT_MS+10u); uds_poll(&m->uds,m->clock); return -1; }
    case A_INTERLEAVE: { uint8_t g[8]={0x10,0x0C,0x22,0x01,0x00,0xDD,0xEE,0xFF}; return feed(m,g,8u,outcome); }
    default: return -1;
    }
}

static const char *aname(int a)
{
    static const char *n[A_COUNT] = {
        "session extended","session default","request seed","correct key",
        "wrong key","ECU reset","read DID","tester present","clear DTC",
        "First Frame","CF correct SN","CF wrong SN","garbage PCI",
        "Flow Control","clock += N_Cr","clock += tick","clock += S3",
        "clock += lockout","interleaved FF" };
    return (a>=0 && a<A_COUNT) ? n[a] : "?";
}

/* ---- Empreinte d'etat : session x securite x ISO-TP x timing ------ */

static uint32_t fingerprint(const model_t *m)
{
    uint32_t fa = (m->uds.failed_attempts > 3u) ? 3u : m->uds.failed_attempts;
    uint32_t tr_active = (m->rx.expected_length > 0u) ? 1u : 0u;
    uint32_t sn = (uint32_t)(m->rx.next_sequence_number & 0x0Fu);
    uint32_t rxst = (uint32_t)m->rx.state;
    uint32_t i, dtc=0u, rl_bucket, reset_flag;

    /* Nombre de codes defaut actifs (0..4) : effacer / regenerer un DFC
       change l'etat, ce qui elargit reellement l'espace atteignable. */
    for (i=0u; i<ECU_DTC_MAX_COUNT; i++) if (m->data.dtc[i].active) dtc++;

    /* Progression d'un reassemblage ISO-TP en cours : combien d'octets
       recus, en tranches. Un transfert profond visite des etats distincts. */
    if (m->rx.received_length==0u) rl_bucket=0u;
    else if (m->rx.received_length<=6u) rl_bucket=1u;
    else if (m->rx.received_length<=13u) rl_bucket=2u;
    else rl_bucket=3u;

    reset_flag = (m->data.reset_count>0u) ? 1u : 0u;

    return ((uint32_t)m->uds.session & 0x3u)
         | (((uint32_t)m->uds.security_level & 0x1u) << 2)
         | (((uint32_t)m->uds.seed_pending & 0x1u) << 3)
         | (((uint32_t)m->uds.locked_out & 0x1u) << 4)
         | ((fa & 0x3u) << 5)
         | ((rxst & 0x1u) << 7)
         | ((tr_active & 0x1u) << 8)
         | ((sn & 0xFu) << 9)
         | ((dtc & 0x7u) << 13)
         | ((rl_bucket & 0x3u) << 16)
         | ((reset_flag & 0x1u) << 18);
}

/* ---- Tables de couverture (open addressing, statiques) ------------ */

#define ST_SIZE (1u<<16)
static uint32_t g_st_key[ST_SIZE];
static uint16_t g_st_cnt[ST_SIZE];
static int g_st_distinct;

#define TR_SIZE (1u<<18)
static uint32_t g_tr_key[TR_SIZE];
static int g_tr_distinct;

static uint8_t g_out_seen[512];
static int g_out_distinct;
static int g_max_depth;

static void cov_reset(void)
{
    memset(g_st_key,0,sizeof(g_st_key));
    memset(g_st_cnt,0,sizeof(g_st_cnt));
    memset(g_tr_key,0,sizeof(g_tr_key));
    memset(g_out_seen,0,sizeof(g_out_seen));
    g_st_distinct=0; g_tr_distinct=0; g_out_distinct=0; g_max_depth=0;
}

static int cov_state(uint32_t fp)
{
    uint32_t k=fp+1u;
    uint32_t h=(fp*2654435761u) & (ST_SIZE-1u);
    for (;;) {
        if (g_st_key[h]==0u){ g_st_key[h]=k; g_st_cnt[h]=1u; g_st_distinct++; return 1; }
        if (g_st_key[h]==k){ if (g_st_cnt[h]<0xFFFFu) g_st_cnt[h]++; return 0; }
        h=(h+1u)&(ST_SIZE-1u);
    }
}

static int cov_transition(uint32_t prev, uint32_t nw)
{
    uint32_t tk=((prev*0x9E3779B1u) ^ (nw+0x85EBCA6Bu));
    uint32_t k=tk|1u;
    uint32_t h=(tk*2246822519u) & (TR_SIZE-1u);
    for (;;) {
        if (g_tr_key[h]==0u){ g_tr_key[h]=k; g_tr_distinct++; return 1; }
        if (g_tr_key[h]==k) return 0;
        h=(h+1u)&(TR_SIZE-1u);
    }
}

static void cov_outcome(int o)
{
    uint32_t idx=((uint32_t)o) & 511u;
    if (g_out_seen[idx]==0u){ g_out_seen[idx]=1u; g_out_distinct++; }
}

#define RARE_THRESHOLD 3u
static int cov_rare(void)
{
    uint32_t i; int rare=0;
    for (i=0;i<ST_SIZE;i++)
        if (g_st_key[i]!=0u && g_st_cnt[i]<=RARE_THRESHOLD) rare++;
    return rare;
}

/* ---- Rejouer / minimiser ------------------------------------------ */

#define MAXSEQ 256

static int replay(const uint8_t *seq, int len)
{
    model_t m; rng_t rng={0x1234u}; int i, o;
    model_init(&m);
    for (i=0;i<len;i++){ int v=apply_act(&m, seq[i], &rng, &o); if (v>=0) return v; }
    if (golden_ok(&m)==0) return HDG_INV_AVAIL_NO_WEDGED_CONTEXT;
    return -1;
}

static int minimize(uint8_t *seq, int len, int target)
{
    int changed=1;
    while (changed){ int i; changed=0;
        for (i=0;i<len;i++){
            uint8_t tmp[MAXSEQ]; int tl=0,j;
            for (j=0;j<len;j++) if (j!=i) tmp[tl++]=seq[j];
            if (replay(tmp,tl)==target){ for(j=0;j<tl;j++) seq[j]=tmp[j]; len=tl; changed=1; i--; }
        }
    }
    return len;
}

/* ---- Resultat d'une campagne -------------------------------------- */

typedef struct {
    uint64_t sequences;
    int states, transitions, outcomes, max_depth, rare;
    double   runtime_s;
    int      cex_found;
    int      cex_inv;
    uint8_t  cex_seq[MAXSEQ];
    int      cex_len;
} camp_t;

/* Novelty : privilegie les etats RARES ; le temps CPU n'entre PAS. */
static double novelty(const camp_t *c)
{
    return (double)c->states
         + 0.4 * (double)c->transitions
         + 3.0 * (double)c->rare
         + 1.0 * (double)c->outcomes
         + 0.1 * (double)c->max_depth;
}

/* ---- Moteur aleatoire (normal / stress, sonde du hunter) ---------- */

static void run_random(uint32_t seed, uint64_t budget, int depth_cap,
                       double deadline, camp_t *out)
{
    rng_t rng={ seed?seed:1u };
    uint64_t n;
    double t0=now_seconds();

    cov_reset();
    memset(out,0,sizeof(*out)); out->cex_inv=-1;

    for (n=0; n<budget; n++)
    {
        model_t m; int len=(int)(rr(&rng)%(uint32_t)depth_cap)+1; int step, o;
        uint8_t seq[MAXSEQ]; uint32_t prev;
        model_init(&m);
        prev=fingerprint(&m); (void)cov_state(prev);

        for (step=0; step<len && step<MAXSEQ; step++)
        {
            int a=(int)(rr(&rng)%(uint32_t)A_COUNT);
            int v; uint32_t fp;
            seq[step]=(uint8_t)a;
            v=apply_act(&m,a,&rng,&o);
            fp=fingerprint(&m);
            (void)cov_state(fp);
            (void)cov_transition(prev,fp);
            if (o) cov_outcome(o);
            prev=fp;
            if (step+1>out->max_depth) out->max_depth=step+1;
            if (v>=0 && out->cex_inv<0){
                memcpy(out->cex_seq, seq, (size_t)(step+1));
                out->cex_len=minimize(out->cex_seq, step+1, v);
                out->cex_inv=v; out->cex_found=1;
            }
            if (v>=0) break;
        }
        out->sequences++;
        if ((deadline>0.0) && ((n & 0xFFFFu)==0u) && (now_seconds()>deadline)) break;
    }
    out->states=g_st_distinct; out->transitions=g_tr_distinct;
    out->outcomes=g_out_distinct; out->rare=cov_rare();
    out->runtime_s=now_seconds()-t0;
}

/* ---- Moteur coverage-guided (deep / extreme) ---------------------- */

#define CORPUS_MAX 4096
typedef struct { uint8_t a[MAXSEQ]; int n; } entry_t;
static entry_t g_corpus[CORPUS_MAX];
static int g_corpus_n;

static void corpus_add(const uint8_t *seq, int len)
{
    if (g_corpus_n>=CORPUS_MAX) return;
    if (len>MAXSEQ) len=MAXSEQ;
    memcpy(g_corpus[g_corpus_n].a, seq, (size_t)len);
    g_corpus[g_corpus_n].n=len;
    g_corpus_n++;
}

static int mutate(const entry_t *src, uint8_t *dst, int depth_cap, rng_t *rng)
{
    int len=src->n, muts, i;
    memcpy(dst, src->a, (size_t)len);
    muts=(int)(rr(rng)%4u)+1;
    for (i=0;i<muts;i++){
        int op=(int)(rr(rng)%5u);
        if (op==0 && len<depth_cap){
            int pos=(int)(rr(rng)%(uint32_t)(len+1)); int k;
            for (k=len;k>pos;k--) dst[k]=dst[k-1];
            dst[pos]=(uint8_t)(rr(rng)%(uint32_t)A_COUNT); len++;
        } else if (op==1 && len>1){
            int pos=(int)(rr(rng)%(uint32_t)len); int k;
            for (k=pos;k<len-1;k++){ dst[k]=dst[k+1]; } len--;
        } else if (op==2 && len>0){
            dst[(int)(rr(rng)%(uint32_t)len)]=(uint8_t)(rr(rng)%(uint32_t)A_COUNT);
        } else if (op==3 && len>0 && len<depth_cap){
            int pos=(int)(rr(rng)%(uint32_t)len);
            int blk=(int)(rr(rng)%4u)+1; int k;
            if (pos+blk>len) blk=len-pos;
            if (blk>0 && len+blk<=depth_cap){
                for (k=len+blk-1;k>=pos+blk;k--) dst[k]=dst[k-blk];
                for (k=0;k<blk;k++) dst[pos+blk+k]=dst[pos+k];
                len+=blk;
            }
        } else if (len<depth_cap){
            dst[len++]=(uint8_t)(rr(rng)%(uint32_t)A_COUNT);
        }
    }
    return len;
}

static int exec_seq(const uint8_t *seq, int len, rng_t *rng, int *viol)
{
    model_t m; int step, o, gained=0; uint32_t prev;
    *viol=-1;
    model_init(&m);
    prev=fingerprint(&m); if (cov_state(prev)) gained=1;
    for (step=0; step<len; step++){
        int v=apply_act(&m,(int)seq[step],rng,&o);
        uint32_t fp=fingerprint(&m);
        if (cov_state(fp)) gained=1;
        if (cov_transition(prev,fp)) gained=1;
        if (o) cov_outcome(o);
        prev=fp;
        if (step+1>g_max_depth) g_max_depth=step+1;
        if (v>=0){ *viol=v; return gained; }
    }
    if (golden_ok(&m)==0){ *viol=HDG_INV_AVAIL_NO_WEDGED_CONTEXT; }
    return gained;
}

static void run_guided(uint32_t seed, uint64_t max_iters, double max_seconds,
                       int depth_cap, int stop_on_cex, camp_t *out)
{
    rng_t rng={ seed?seed:1u };
    double t0=now_seconds(), last=t0;
    uint64_t it=0, since_gain=0;
    const uint64_t plateau_iters=300000u;
    uint8_t buf[MAXSEQ];
    int s;

    cov_reset();
    g_corpus_n=0; g_max_depth=0;
    memset(out,0,sizeof(*out)); out->cex_inv=-1;

    for (s=0;s<8;s++){
        int len=(int)(rr(&rng)%8u)+1,k,viol; uint8_t seq[8];
        for (k=0;k<len;k++) seq[k]=(uint8_t)(rr(&rng)%(uint32_t)A_COUNT);
        (void)exec_seq(seq,len,&rng,&viol);
        corpus_add(seq,len);
    }

    for (;;)
    {
        int len, viol, gained;
        if (max_iters && it>=max_iters) break;

        if (g_corpus_n==0){
            int k; len=(int)(rr(&rng)%8u)+1;
            for (k=0;k<len;k++) buf[k]=(uint8_t)(rr(&rng)%(uint32_t)A_COUNT);
        } else {
            int pick=(int)(rr(&rng)%(uint32_t)g_corpus_n);
            len=mutate(&g_corpus[pick], buf, depth_cap, &rng);
        }

        gained=exec_seq(buf,len,&rng,&viol);
        it++;
        if (gained){ corpus_add(buf,len); since_gain=0; } else since_gain++;

        if (viol>=0 && out->cex_inv<0){
            memcpy(out->cex_seq, buf, (size_t)len);
            out->cex_len=minimize(out->cex_seq, len, viol);
            out->cex_inv=viol; out->cex_found=1;
            if (stop_on_cex) break;
        }

        if (now_seconds()-last > 2.0){
            last=now_seconds();
            printf("  it=%-10llu  states=%-4d transitions=%-6d rare=%-4d "
                   "corpus=%-4d depth=%d  (%.0fs)\n",
                   (unsigned long long)it, g_st_distinct, g_tr_distinct,
                   cov_rare(), g_corpus_n, g_max_depth, now_seconds()-t0);
            fflush(stdout);
        }
        if (since_gain>=plateau_iters){
            printf("  [plateau : aucune nouvelle couverture depuis %llu iterations]\n",
                   (unsigned long long)plateau_iters);
            break;
        }
        if (max_seconds>0.0 && (now_seconds()-t0)>max_seconds){
            printf("  [delai atteint : %.0f s]\n", max_seconds);
            break;
        }
    }

    out->sequences=it;
    out->states=g_st_distinct; out->transitions=g_tr_distinct;
    out->outcomes=g_out_distinct; out->rare=cov_rare();
    out->max_depth=g_max_depth; out->runtime_s=now_seconds()-t0;
}

/* ---- Rapport ------------------------------------------------------ */

static void report_campaign(const char *title, const camp_t *c)
{
    printf("\n=== %s ===\n", title);
    printf("  sequences     : %llu\n", (unsigned long long)c->sequences);
    printf("  etats         : %d\n", c->states);
    printf("  transitions   : %d\n", c->transitions);
    printf("  issues        : %d\n", c->outcomes);
    printf("  etats rares   : %d\n", c->rare);
    printf("  profondeur max: %d\n", c->max_depth);
    printf("  duree         : %.1f s\n", c->runtime_s);
    if (c->cex_found){
        const hdg_invariant_info_t *info=hdg_invariant_info((hdg_invariant_id_t)c->cex_inv);
        int i;
        printf("  CONTRE-EXEMPLE: invariant %s (%d trames)\n",
               info?info->code:"?", c->cex_len);
        for (i=0;i<c->cex_len;i++) printf("     %2d. %s\n", i+1, aname(c->cex_seq[i]));
    } else {
        printf("  contre-exemple: aucun (assurance bornee)\n");
    }
}

/* ---- Seed Hunter -------------------------------------------------- */

typedef struct { uint32_t seed; camp_t c; double nov; } hunt_row_t;

static int cmp_row(const void *a, const void *b)
{
    double na=((const hunt_row_t*)a)->nov, nb=((const hunt_row_t*)b)->nov;
    return (na<nb)?1:((na>nb)?-1:0);
}

static void seed_hunter(int n_seeds, int attack)
{
    static const uint32_t CLASSICS[] = {
        0x00000001u,0xDEADBEEFu,0x9E3779B9u,0x00C0FFEEu,0x000A11CEu,0x0BADC0DEu,
        0x0000F00Du,0x0005EED1u,0x00001234u,0x0000B0A7u,0x8128AB91u,0x71C493DEu };
    hunt_row_t *rows;
    int i, nc=(int)(sizeof(CLASSICS)/sizeof(CLASSICS[0]));
    double best_nov=0.0, maxnov=0.0; uint32_t best_seed=0u;
    rng_t gen={0x0000A5A5u};

    if (n_seeds<nc) n_seeds=nc;
    rows=(hunt_row_t*)calloc((size_t)n_seeds, sizeof(hunt_row_t));
    if (rows==NULL){ printf("memoire insuffisante\n"); return; }

    printf("============================================================\n");
    printf(" AHDG Seed Hunter — classement par NOUVEAUTE, pas par CPU\n");
    printf("============================================================\n");
    printf(" %d seeds, sonde 30000 sequences (profondeur 16) chacun\n\n", n_seeds);
    printf(" %-12s %7s %12s %7s %8s %10s\n",
           "seed","etats","transitions","rares","novelty","runtime");
    printf(" ----------------------------------------------------------------\n");

    for (i=0;i<n_seeds;i++){
        uint32_t seed = (i<nc) ? CLASSICS[i] : rr(&gen);
        camp_t c;
        run_random(seed, 30000u, 16, 0.0, &c);
        rows[i].seed=seed; rows[i].c=c; rows[i].nov=novelty(&c);
        if (rows[i].nov>maxnov) maxnov=rows[i].nov;
    }
    if (maxnov<=0.0) maxnov=1.0;

    qsort(rows, (size_t)n_seeds, sizeof(hunt_row_t), cmp_row);

    for (i=0;i<n_seeds;i++){
        printf(" 0x%08X %7d %12d %7d %8.2f %8.0f ms\n",
               rows[i].seed, rows[i].c.states, rows[i].c.transitions,
               rows[i].c.rare, rows[i].nov/maxnov, rows[i].c.runtime_s*1000.0);
        if (i==0){ best_nov=rows[i].nov; best_seed=rows[i].seed; }
    }

    printf("\n HARDEST SEED FOUND : 0x%08X   (novelty %.2f)\n",
           best_seed, best_nov/maxnov);
    printf("   score = etats + 0.4*transitions + 3*rares + issues + 0.1*profondeur\n");
    printf("   (le temps CPU n'entre PAS dans le score)\n");
    printf("============================================================\n");

    free(rows);

    if (attack){
        camp_t c;
        printf("\n>>> Attack hardest seed 0x%08X (DEEP coverage-guided, 20 s max)\n",
               best_seed);
        run_guided(best_seed, 0u, 20.0, 64, 1, &c);
        report_campaign("Campagne sur le seed le plus dur", &c);
    }
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
    printf("usage : ahdg_hunt <mode> [args]\n");
    printf("  normal  [seed] [budget]         1M seq, profondeur 8\n");
    printf("  stress  [seed] [budget]         100M seq, profondeur 64\n");
    printf("  deep    [seed] [max_iters]      coverage-guided, profondeur 256\n");
    printf("  extreme [seed] [max_seconds]    jusqu'a cex | plateau | delai\n");
    printf("  hunt    [n_seeds] [attack:0/1]  chasseur de graines\n");
}

int main(int argc, char **argv)
{
    if (argc<2){ usage(); return 1; }

    if (strcmp(argv[1],"normal")==0){
        uint32_t seed=(argc>2)?(uint32_t)strtoul(argv[2],NULL,0):0x000A11CEu;
        uint64_t budget=(argc>3)?strtoull(argv[3],NULL,10):1000000u;
        camp_t c;
        printf("Mode NORMAL : %llu sequences, profondeur <= 8, seed 0x%08X\n",
               (unsigned long long)budget, seed);
        run_random(seed, budget, 8, 0.0, &c);
        report_campaign("NORMAL", &c);
        return c.cex_found?2:0;
    }
    if (strcmp(argv[1],"stress")==0){
        uint32_t seed=(argc>2)?(uint32_t)strtoul(argv[2],NULL,0):0x0000F00Du;
        uint64_t budget=(argc>3)?strtoull(argv[3],NULL,10):100000000u;
        camp_t c;
        printf("Mode STRESS : %llu sequences, profondeur <= 64, seed 0x%08X\n",
               (unsigned long long)budget, seed);
        run_random(seed, budget, 64, 0.0, &c);
        report_campaign("STRESS", &c);
        return c.cex_found?2:0;
    }
    if (strcmp(argv[1],"deep")==0){
        uint32_t seed=(argc>2)?(uint32_t)strtoul(argv[2],NULL,0):0x71C493DEu;
        uint64_t iters=(argc>3)?strtoull(argv[3],NULL,10):2000000u;
        camp_t c;
        printf("Mode DEEP ADVERSARIAL : coverage-guided, profondeur <= 256, seed 0x%08X\n", seed);
        run_guided(seed, iters, 0.0, 256, 1, &c);
        report_campaign("DEEP ADVERSARIAL", &c);
        return c.cex_found?2:0;
    }
    if (strcmp(argv[1],"extreme")==0){
        uint32_t seed=(argc>2)?(uint32_t)strtoul(argv[2],NULL,0):0x71C493DEu;
        double secs=(argc>3)?strtod(argv[3],NULL):30.0;
        camp_t c;
        printf("Mode EXTREME RESEARCH : run until counterexample | plateau | %.0f s, seed 0x%08X\n",
               secs, seed);
        run_guided(seed, 0u, secs, 256, 1, &c);
        report_campaign("EXTREME RESEARCH", &c);
        return c.cex_found?2:0;
    }
    if (strcmp(argv[1],"hunt")==0){
        int n=(argc>2)?atoi(argv[2]):24;
        int attack=(argc>3)?atoi(argv[3]):0;
        seed_hunter(n, attack);
        return 0;
    }

    usage();
    return 1;
}
