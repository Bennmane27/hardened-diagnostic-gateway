/*
 * ahdg_frames.c
 *
 * Explorateur adversarial au niveau des TRAMES CAN.
 *
 * L'explorateur UDS (ahdg_explore.c) attaque le serveur au niveau
 * applicatif. Celui-ci descend d'un cran : il compose des sequences de
 * vraies trames CAN — Single Frame, First Frame, Consecutive Frame,
 * Flow Control, trames invalides, transferts entrelaces, sauts d'horloge
 * — et les injecte dans le VRAI pipeline isotp_rx + uds, exactement comme
 * l'ECU les recevrait.
 *
 * Il cherche deux choses qu'on ne peut voir qu'a ce niveau :
 *
 *   - une CONFUSION CROSS-LAYER : une manipulation du transport
 *     (desynchronisation ISO-TP) qui ferait accepter une autorite UDS
 *     illegitime — le coeur de la contribution AHDG ;
 *
 *   - une atteinte a la DISPONIBILITE : une sequence hostile qui
 *     laisserait l'ECU incapable de servir une requete legitime ensuite
 *     (le deni de diagnostic, classe visee par les travaux ISO-TP 2026).
 *
 * Apres chaque sequence hostile, une SONDE DOREE (deux requetes valides)
 * verifie que l'ECU repond encore correctement : rejeter une attaque ne
 * vaut rien si le contexte reste casse (invariant AVAIL-2).
 *
 * Deterministe, minimisation par delta-debug. Resultat honnete attendu :
 * la discipline de reinitialisation stricte d'isotp_rx empeche le
 * transport de forger une autorite ; l'explorateur en apporte la preuve
 * bornee, ou trouve un contre-exemple.
 *
 * Build : make frames
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"
#include "invariants.h"

/* ------------------------------------------------------------------ */
/* Generateur reproductible                                            */
/* ------------------------------------------------------------------ */

static uint32_t g_rng;
static uint32_t rng_next(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
    return g_rng;
}

/* ------------------------------------------------------------------ */
/* Modele ECU : le vrai pipeline transport + application               */
/* ------------------------------------------------------------------ */

typedef struct
{
    isotp_rx_context_t rx;
    uds_context_t      uds;
    ecu_data_t         data;
    uint32_t           clock;
} ecu_model_t;

static void model_init(ecu_model_t *m)
{
    isotp_rx_init(&m->rx);
    ecu_data_init(&m->data);
    uds_init(&m->uds);
    uds_set_did_provider(&m->uds, ecu_data_read_did, &m->data);
    uds_set_dtc_provider(&m->uds, ecu_data_read_dtc, ecu_data_clear_dtc);
    uds_set_reset_handler(&m->uds, ecu_data_reset);
    m->clock = 1000u;
}

typedef struct
{
    uds_session_t session;
    uint8_t security_level;
    uint8_t seed_pending;
    uint8_t failed_attempts;
    uint8_t locked_out;
} snap_t;

static snap_t snap(const uds_context_t *c)
{
    snap_t s;
    s.session=c->session; s.security_level=c->security_level;
    s.seed_pending=c->seed_pending; s.failed_attempts=c->failed_attempts;
    s.locked_out=c->locked_out;
    return s;
}

/* Les invariants UDS, memes IDs que le catalogue (invariants.h). */
static int check_uds(const snap_t *pre, const uds_context_t *post,
                     const uint8_t *resp, uint16_t rl)
{
    int pr = (rl>=1u)&&(resp[0]==0x51u);
    int pk = (rl>=2u)&&(resp[0]==0x67u)&&(resp[1]==0x02u);
    if (pr && (pre->security_level==UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_NO_UNAUTH_EFFECT;
    if (pk && (pre->seed_pending==0u))
        return HDG_INV_SEC_SEED_KEY_BINDING;
    if (pr && (post->security_level!=UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_RELOCK_ON_RESET;
    if (pr && (post->seed_pending!=0u))
        return HDG_INV_XL_NO_AUTHORITY_CARRYOVER;
    if ((post->session==UDS_SESSION_DEFAULT) &&
        (post->security_level!=UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_RELOCK_ON_DEFAULT;
    return -1;
}

/*
 * Injecte une trame CAN dans le pipeline. Si un message UDS se
 * reassemble, il est traite par le serveur. Renvoie l'ID d'un invariant
 * viole, ou -1. La longueur reassemblee ne doit jamais depasser
 * l'annonce : invariant TP verifie explicitement.
 */
static int feed(ecu_model_t *m, const uint8_t *frame, uint8_t len)
{
    isotp_rx_result_t rxo;
    m->clock += 1u;
    (void)isotp_rx_process(&m->rx, frame, len, m->clock, &rxo);

    /* Invariant transport : jamais plus recu qu'annonce. */
    if (m->rx.received_length > m->rx.expected_length)
    {
        return HDG_INV_TP_LENGTH_HONESTY;
    }

    if (rxo.event == ISOTP_RX_EVENT_MESSAGE_READY)
    {
        uint8_t resp[UDS_MAX_RESPONSE_SIZE];
        uint16_t rl = 0u;
        snap_t pre = snap(&m->uds);

        /* XL-1 : un message ne doit jamais depasser le tampon. */
        if (rxo.message_len > ISOTP_MAX_PAYLOAD_SIZE)
        {
            return HDG_INV_XL_TRANSPORT_CANNOT_FORGE_AUTHORITY;
        }

        (void)uds_handle_request(&m->uds, rxo.message, rxo.message_len,
                                 m->clock, resp, (uint16_t)sizeof(resp), &rl);
        return check_uds(&pre, &m->uds, resp, rl);
    }
    return -1;
}

/* Sonde doree : l'ECU repond-il encore a une requete legitime ? */
static int golden_ok(ecu_model_t *m)
{
    uint8_t sf1[8] = { 0x02, 0x10, 0x03, 0,0,0,0,0 };  /* session extended */
    uint8_t sf2[8] = { 0x03, 0x22, 0xF1, 0x89, 0,0,0,0 }; /* read sw version */
    isotp_rx_result_t rxo;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t rl;
    int ok1 = 0, ok2 = 0;

    m->clock += 1u;
    (void)isotp_rx_process(&m->rx, sf1, 8u, m->clock, &rxo);
    if (rxo.event == ISOTP_RX_EVENT_MESSAGE_READY)
    {
        rl = 0u;
        (void)uds_handle_request(&m->uds, rxo.message, rxo.message_len,
                                 m->clock, resp, (uint16_t)sizeof(resp), &rl);
        ok1 = (rl >= 1u) && (resp[0] == 0x50u);
    }

    m->clock += 1u;
    (void)isotp_rx_process(&m->rx, sf2, 8u, m->clock, &rxo);
    if (rxo.event == ISOTP_RX_EVENT_MESSAGE_READY)
    {
        rl = 0u;
        (void)uds_handle_request(&m->uds, rxo.message, rxo.message_len,
                                 m->clock, resp, (uint16_t)sizeof(resp), &rl);
        ok2 = (rl >= 1u) && (resp[0] == 0x62u);
    }
    return (ok1 && ok2) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Alphabet de trames                                                  */
/* ------------------------------------------------------------------ */

typedef enum
{
    F_SF_SESSION_EXT = 0, F_SF_SESSION_DEF, F_SF_SEED, F_SF_KEY_CORRECT,
    F_SF_KEY_WRONG, F_SF_RESET, F_SF_READ, F_SF_PRESENT,
    F_FF20, F_CF_GOOD, F_CF_BAD, F_GARBAGE, F_UNEXPECTED_FC,
    F_CLOCK_NCR, F_INTERLEAVE_FF,
    F_COUNT
} frame_act_t;

static const char *fname(frame_act_t a)
{
    switch (a) {
    case F_SF_SESSION_EXT:  return "SF: session extended (02 10 03)";
    case F_SF_SESSION_DEF:  return "SF: session default (02 10 01)";
    case F_SF_SEED:         return "SF: request seed (02 27 01)";
    case F_SF_KEY_CORRECT:  return "SF: correct key (legit unlock)";
    case F_SF_KEY_WRONG:    return "SF: wrong key";
    case F_SF_RESET:        return "SF: ECU reset (02 11 01)";
    case F_SF_READ:         return "SF: read DID (03 22 F1 90)";
    case F_SF_PRESENT:      return "SF: tester present (02 3E 00)";
    case F_FF20:            return "FF: First Frame, 20 bytes (10 14 ...)";
    case F_CF_GOOD:         return "CF: correct sequence number";
    case F_CF_BAD:          return "CF: wrong sequence number";
    case F_GARBAGE:         return "invalid PCI type (4..15)";
    case F_UNEXPECTED_FC:   return "unexpected Flow Control (30 00 00)";
    case F_CLOCK_NCR:       return "clock += N_Cr (transfer timeout)";
    case F_INTERLEAVE_FF:   return "interleaved First Frame (10 0C ...)";
    default:                return "?";
    }
}

/* Applique une trame-action. Renvoie l'ID d'un invariant viole, ou -1. */
static int apply_frame(ecu_model_t *m, frame_act_t a)
{
    uint8_t f[8];
    memset(f, 0, sizeof(f));

    switch (a) {
    case F_SF_SESSION_EXT: f[0]=0x02; f[1]=0x10; f[2]=0x03; return feed(m,f,8u);
    case F_SF_SESSION_DEF: f[0]=0x02; f[1]=0x10; f[2]=0x01; return feed(m,f,8u);
    case F_SF_SEED:        f[0]=0x02; f[1]=0x27; f[2]=0x01; return feed(m,f,8u);
    case F_SF_KEY_CORRECT: {
        uint32_t k = uds_demo_key_from_seed(m->uds.current_seed);
        uint8_t g[8]; memset(g,0,sizeof(g));
        g[0]=0x05; g[1]=0x27; g[2]=0x02;
        g[3]=(uint8_t)(k>>24); g[4]=(uint8_t)(k>>16);
        g[5]=(uint8_t)(k>>8);  g[6]=(uint8_t)k;
        return feed(m,g,8u);
    }
    case F_SF_KEY_WRONG: {
        uint8_t g[8]={0x05,0x27,0x02,0xDE,0xAD,0xBE,0xEF,0x00};
        return feed(m,g,8u);
    }
    case F_SF_RESET:    f[0]=0x02; f[1]=0x11; f[2]=0x01; return feed(m,f,8u);
    case F_SF_READ:     f[0]=0x03; f[1]=0x22; f[2]=0xF1; f[3]=0x90; return feed(m,f,8u);
    case F_SF_PRESENT:  f[0]=0x02; f[1]=0x3E; f[2]=0x00; return feed(m,f,8u);

    case F_FF20: {
        uint8_t g[8]={0x10,0x14,0x22,0xF1,0x90,0xAA,0xBB,0xCC};
        return feed(m,g,8u);
    }
    case F_CF_GOOD: {
        uint8_t sn = m->rx.next_sequence_number;
        f[0]=(uint8_t)(0x20u|(sn&0x0Fu));
        f[1]=1;f[2]=2;f[3]=3;f[4]=4;f[5]=5;f[6]=6;f[7]=7;
        return feed(m,f,8u);
    }
    case F_CF_BAD: {
        f[0]=0x2F;  /* sequence 15, presque toujours fausse */
        f[1]=1;f[2]=2;f[3]=3;f[4]=4;f[5]=5;f[6]=6;f[7]=7;
        return feed(m,f,8u);
    }
    case F_GARBAGE: {
        f[0]=(uint8_t)(((rng_next()%12u)+4u)<<4);
        return feed(m,f,(uint8_t)((rng_next()%8u)+1u));
    }
    case F_UNEXPECTED_FC: { uint8_t g[8]={0x30,0,0,0,0,0,0,0}; return feed(m,g,8u); }
    case F_CLOCK_NCR: {
        isotp_rx_result_t rxo;
        m->clock += (ISOTP_N_CR_TIMEOUT_MS + 10u);
        (void)isotp_rx_poll_timeout(&m->rx, m->clock, &rxo);
        return -1;
    }
    case F_INTERLEAVE_FF: {
        uint8_t g[8]={0x10,0x0C,0x22,0x01,0x00,0xDD,0xEE,0xFF};
        return feed(m,g,8u);
    }
    default: return -1;
    }
}

/* ------------------------------------------------------------------ */
/* Rejouer / minimiser                                                 */
/*                                                                     */
/* Une violation peut apparaitre pendant la sequence (invariant UDS/TP)*/
/* OU a la fin (AVAIL : la sonde doree echoue).                        */
/* ------------------------------------------------------------------ */

#define MAXSEQ 48

static int replay(const frame_act_t *seq, int len)
{
    ecu_model_t m;
    int i;
    model_init(&m);
    for (i=0;i<len;i++) {
        int v = apply_frame(&m, seq[i]);
        if (v>=0) return v;
    }
    if (golden_ok(&m)==0) return HDG_INV_AVAIL_NO_WEDGED_CONTEXT;
    return -1;
}

static int minimize(frame_act_t *seq, int len, int target)
{
    int changed=1;
    while (changed) {
        int i; changed=0;
        for (i=0;i<len;i++) {
            frame_act_t tmp[MAXSEQ]; int tl=0,j;
            for (j=0;j<len;j++) if (j!=i) tmp[tl++]=seq[j];
            if (replay(tmp,tl)==target) {
                for (j=0;j<tl;j++) seq[j]=tmp[j];
                len=tl; changed=1; i--;
            }
        }
    }
    return len;
}

/* ------------------------------------------------------------------ */

static const int EVAL[] = {
    HDG_INV_SEC_NO_UNAUTH_EFFECT, HDG_INV_SEC_SEED_KEY_BINDING,
    HDG_INV_SEC_RELOCK_ON_RESET,  HDG_INV_SEC_RELOCK_ON_DEFAULT,
    HDG_INV_XL_NO_AUTHORITY_CARRYOVER,
    HDG_INV_XL_TRANSPORT_CANNOT_FORGE_AUTHORITY,
    HDG_INV_TP_LENGTH_HONESTY,
    HDG_INV_AVAIL_NO_WEDGED_CONTEXT
};
#define EVAL_COUNT ((int)(sizeof(EVAL)/sizeof(EVAL[0])))

int main(int argc, char **argv)
{
    uint64_t budget = 300000u;
    uint32_t seed = 0xF00D;
    uint64_t n;
    uint64_t frames_total = 0u, msgs_total = 0u;
    int found[HDG_INV_COUNT];
    int i;

    if (argc>1) budget = strtoull(argv[1],NULL,10);
    if (argc>2) seed = (uint32_t)strtoul(argv[2],NULL,0);
    for (i=0;i<HDG_INV_COUNT;i++) found[i]=0;
    g_rng = (seed!=0u)?seed:1u;

    printf("============================================================\n");
    printf(" AHDG — exploration adversariale au niveau des trames CAN\n");
    printf("============================================================\n");
    printf(" cible     : isotp_rx + uds (pipeline reel)\n");
    printf(" sequences : %llu\n", (unsigned long long)budget);
    printf(" graine    : 0x%08X\n\n", seed);

    for (n=0;n<budget;n++) {
        ecu_model_t m;
        frame_act_t seq[MAXSEQ];
        int len = (int)(rng_next()%20u)+1;
        int step, viol=-1;

        model_init(&m);
        for (step=0; step<len; step++) {
            frame_act_t a = (frame_act_t)(rng_next()%(uint32_t)F_COUNT);
            seq[step]=a;
            frames_total++;
            viol = apply_frame(&m, a);
            if (m.rx.state==ISOTP_RX_IDLE) { /* etat borne, ok */ }
            if (viol>=0) break;
        }
        msgs_total += m.rx.stat_messages;

        /* AVAIL en fin de sequence si rien n'a casse avant. */
        if (viol<0 && golden_ok(&m)==0) {
            viol = HDG_INV_AVAIL_NO_WEDGED_CONTEXT;
            len = step; /* la sonde n'est pas dans la sequence */
        } else if (viol>=0) {
            len = step+1;
        }

        if (viol>=0 && found[viol]==0) {
            int ml = minimize(seq, len, viol);
            const hdg_invariant_info_t *info =
                hdg_invariant_info((hdg_invariant_id_t)viol);
            found[viol]=1;
            printf("============================================================\n");
            printf(" CONTRE-EXEMPLE — invariant %s\n",
                   info?info->code:"?");
            if (info) printf(" %s\n", info->summary);
            printf(" sequence minimale : %d trame(s)\n", ml);
            for (i=0;i<ml;i++) printf("   %2d. %s\n", i+1, fname(seq[i]));
            printf("============================================================\n\n");
        }
    }

    printf("============================================================\n");
    printf(" Bilan\n");
    printf("============================================================\n");
    printf(" sequences jouees   : %llu\n", (unsigned long long)budget);
    printf(" trames injectees   : %llu\n", (unsigned long long)frames_total);
    printf(" messages reassembles : %llu\n\n", (unsigned long long)msgs_total);
    {
        int total=0;
        for (i=0;i<EVAL_COUNT;i++) {
            int id=EVAL[i];
            const hdg_invariant_info_t *info =
                hdg_invariant_info((hdg_invariant_id_t)id);
            printf("   %-8s %s\n", info?info->code:"?",
                   found[id]?"CONTRE-EXEMPLE TROUVE"
                            :"aucun contre-exemple (assurance bornee)");
            if (found[id]) total++;
        }
        printf("\n Contre-exemples : %d\n", total);
        printf("============================================================\n");
        return (total==0)?0:2;
    }
}
