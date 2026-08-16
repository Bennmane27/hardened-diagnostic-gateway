/*
 * ahdg_explore.c
 *
 * Explorateur adversarial de l'espace d'etats UDS.
 *
 * Ce n'est pas le fuzzer d'octets (fuzz_parser.c) : celui-ci n'envoie pas
 * de bruit, il compose des SEQUENCES d'actions de diagnostic plausibles et
 * cherche a conduire le VRAI serveur uds.c dans un etat interdit du
 * catalogue src/gateway/invariants.h.
 *
 * C'est la premiere brique de l'adversaire AHDG, et la reponse concrete a
 * la question "peux-tu contourner ta propre securite ?" : ici l'attaquant,
 * c'est ce programme, et la cible, c'est le code de production.
 *
 * Trois proprietes le rendent utilisable comme instrument de recherche :
 *
 *   - il attaque le code reel, pas une reimplementation ; une violation
 *     trouvee ici est une vraie violation ;
 *   - il est deterministe (graine explicite, aucune entropie injectee dans
 *     le generateur de graines UDS), donc toute decouverte se rejoue ;
 *   - quand il trouve une sequence fautive, il la MINIMISE par delta-debug
 *     jusqu'a un contre-exemple irreductible, et l'EXPLIQUE.
 *
 * Resultat honnete attendu : soit un contre-exemple minimal reproductible,
 * soit "aucun contre-exemple en N sequences" — une assurance bornee, pas
 * une preuve. Les deux sont des resultats.
 *
 * Build :
 *   make explore
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "uds.h"
#include "invariants.h"

/* ------------------------------------------------------------------ */
/* Generateur reproductible                                            */
/* ------------------------------------------------------------------ */

static uint32_t g_rng;

static uint32_t rng_next(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

/* ------------------------------------------------------------------ */
/* Fournisseurs applicatifs (factices, deterministes)                  */
/* ------------------------------------------------------------------ */

static uds_result_t did_read(uint16_t did, uint8_t *out, uint16_t cap,
                             uint16_t *len, void *ctx)
{
    (void)ctx;
    if (cap < 2u) { return UDS_ERR_BUFFER_TOO_SMALL; }
    out[0] = (uint8_t)(did >> 8);
    out[1] = (uint8_t)did;
    *len = 2u;
    return UDS_OK;
}

static uds_result_t dtc_read(uint8_t mask, uint8_t *out, uint16_t cap,
                             uint16_t *len, void *ctx)
{
    (void)mask; (void)out; (void)cap; (void)ctx;
    *len = 0u;
    return UDS_OK;
}

static uds_result_t dtc_clear(uint32_t group, void *ctx)
{
    (void)ctx;
    return (group == 0xFFFFFFu) ? UDS_OK : UDS_ERR_DID_NOT_FOUND;
}

static uds_result_t ecu_reset(uint8_t type, void *ctx)
{
    (void)type; (void)ctx;
    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* Alphabet d'actions                                                  */
/*                                                                     */
/* L'attaquant NE connait PAS la cle : il ne peut la calculer que via   */
/* ACT_KEY_CORRECT, qui modelise un deverrouillage legitime. On l'inclut*/
/* pour pouvoir ATTEINDRE l'etat deverrouille et verifier ensuite que   */
/* les invariants de reverrouillage (SEC-3, SEC-4) tiennent. Les autres */
/* actions cle sont hostiles.                                          */
/* ------------------------------------------------------------------ */

typedef enum
{
    ACT_SESSION_DEFAULT = 0,
    ACT_SESSION_EXTENDED,
    ACT_SESSION_PROGRAMMING,
    ACT_READ_DID,
    ACT_TESTER_PRESENT,
    ACT_SEED_REQUEST,
    ACT_KEY_CORRECT,      /* deverrouillage legitime (oracle) */
    ACT_KEY_WRONG,
    ACT_KEY_REPLAY,       /* rejoue la derniere cle envoyee   */
    ACT_ECU_RESET,
    ACT_CLEAR_DTC,
    ACT_CLOCK_PAST_S3,    /* avance l'horloge au-dela de S3    */
    ACT_CLOCK_SMALL,
    ACT_CLOCK_PAST_LOCKOUT,
    ACT_COUNT
} action_t;

static const char *action_name(action_t a)
{
    switch (a)
    {
    case ACT_SESSION_DEFAULT:     return "session default";
    case ACT_SESSION_EXTENDED:    return "session extended";
    case ACT_SESSION_PROGRAMMING: return "session programming";
    case ACT_READ_DID:            return "read DID";
    case ACT_TESTER_PRESENT:      return "tester present";
    case ACT_SEED_REQUEST:        return "security: request seed";
    case ACT_KEY_CORRECT:         return "security: send correct key (legit)";
    case ACT_KEY_WRONG:           return "security: send wrong key";
    case ACT_KEY_REPLAY:          return "security: replay last key";
    case ACT_ECU_RESET:           return "ECU reset";
    case ACT_CLEAR_DTC:           return "clear DTC";
    case ACT_CLOCK_PAST_S3:       return "clock += S3 timeout";
    case ACT_CLOCK_SMALL:         return "clock += small";
    case ACT_CLOCK_PAST_LOCKOUT:  return "clock += lockout";
    default:                      return "?";
    }
}

/* Etat mutable de l'attaquant entre deux actions. */
typedef struct
{
    uint32_t clock;
    uint8_t  last_key[4];
    int      have_last_key;
} attacker_t;

/* Instantane des champs pertinents avant une action. */
typedef struct
{
    uds_session_t session;
    uint8_t security_level;
    uint8_t seed_pending;
    uint8_t failed_attempts;
    uint8_t locked_out;
} snap_t;

static snap_t snapshot(const uds_context_t *ctx)
{
    snap_t s;
    s.session         = ctx->session;
    s.security_level  = ctx->security_level;
    s.seed_pending    = ctx->seed_pending;
    s.failed_attempts = ctx->failed_attempts;
    s.locked_out      = ctx->locked_out;
    return s;
}

/*
 * Applique une action au serveur reel. Remplit resp/resp_len avec la
 * reponse UDS produite (0 si aucune).
 */
static void apply_action(uds_context_t *ctx, attacker_t *atk, action_t a,
                         uint8_t *resp, uint16_t *resp_len)
{
    uint8_t req[8];
    uint16_t req_len = 0u;

    *resp_len = 0u;

    switch (a)
    {
    case ACT_SESSION_DEFAULT:
        req[0] = 0x10; req[1] = 0x01; req_len = 2u; break;
    case ACT_SESSION_EXTENDED:
        req[0] = 0x10; req[1] = 0x03; req_len = 2u; break;
    case ACT_SESSION_PROGRAMMING:
        req[0] = 0x10; req[1] = 0x02; req_len = 2u; break;
    case ACT_READ_DID:
        req[0] = 0x22; req[1] = 0xF1; req[2] = 0x90; req_len = 3u; break;
    case ACT_TESTER_PRESENT:
        req[0] = 0x3E; req[1] = 0x00; req_len = 2u; break;
    case ACT_SEED_REQUEST:
        req[0] = 0x27; req[1] = 0x01; req_len = 2u; break;

    case ACT_KEY_CORRECT:
    {
        /* Oracle : calcule la cle attendue de la graine courante. */
        uint32_t key = uds_demo_key_from_seed(ctx->current_seed);
        req[0] = 0x27; req[1] = 0x02;
        req[2] = (uint8_t)(key >> 24); req[3] = (uint8_t)(key >> 16);
        req[4] = (uint8_t)(key >> 8);  req[5] = (uint8_t)key;
        req_len = 6u;
        atk->last_key[0] = req[2]; atk->last_key[1] = req[3];
        atk->last_key[2] = req[4]; atk->last_key[3] = req[5];
        atk->have_last_key = 1;
        break;
    }
    case ACT_KEY_WRONG:
        req[0] = 0x27; req[1] = 0x02;
        req[2] = 0xDE; req[3] = 0xAD; req[4] = 0xBE; req[5] = 0xEF;
        req_len = 6u;
        atk->last_key[0] = 0xDE; atk->last_key[1] = 0xAD;
        atk->last_key[2] = 0xBE; atk->last_key[3] = 0xEF;
        atk->have_last_key = 1;
        break;

    case ACT_KEY_REPLAY:
        req[0] = 0x27; req[1] = 0x02;
        if (atk->have_last_key != 0)
        {
            req[2] = atk->last_key[0]; req[3] = atk->last_key[1];
            req[4] = atk->last_key[2]; req[5] = atk->last_key[3];
        }
        else
        {
            req[2] = 0; req[3] = 0; req[4] = 0; req[5] = 0;
        }
        req_len = 6u;
        break;

    case ACT_ECU_RESET:
        req[0] = 0x11; req[1] = 0x01; req_len = 2u; break;
    case ACT_CLEAR_DTC:
        req[0] = 0x14; req[1] = 0xFF; req[2] = 0xFF; req[3] = 0xFF;
        req_len = 4u; break;

    case ACT_CLOCK_PAST_S3:
        atk->clock += (UDS_S3_SERVER_TIMEOUT_MS + 10u);
        uds_poll(ctx, atk->clock);
        return;
    case ACT_CLOCK_SMALL:
        atk->clock += 5u;
        uds_poll(ctx, atk->clock);
        return;
    case ACT_CLOCK_PAST_LOCKOUT:
        atk->clock += (UDS_SECURITY_LOCKOUT_MS + 10u);
        uds_poll(ctx, atk->clock);
        return;

    default:
        return;
    }

    (void)uds_handle_request(ctx, req, req_len, atk->clock,
                             resp, 64, resp_len);
}

/* ------------------------------------------------------------------ */
/* Oracle : evaluation des invariants                                  */
/*                                                                     */
/* Renvoie l'ID de l'invariant viole, ou -1. Volontairement            */
/* conservateur : chaque test est justifie pour eviter tout faux       */
/* positif.                                                            */
/* ------------------------------------------------------------------ */

static int check_invariants(const snap_t *pre, const uds_context_t *post,
                            action_t a, const uint8_t *resp, uint16_t rlen)
{
    int positive_reset = (rlen >= 1u) && (resp[0] == 0x51u);
    int positive_key   = (rlen >= 2u) && (resp[0] == 0x67u) &&
                         (resp[1] == 0x02u);

    /* SEC-1 : aucun effet positif d'ECUReset si on entrait verrouille. */
    if (positive_reset && (pre->security_level == UDS_SECURITY_LOCKED))
    {
        return HDG_INV_SEC_NO_UNAUTH_EFFECT;
    }

    /* SEC-2 : une cle acceptee exige une graine en attente a l'entree. */
    if (positive_key && (pre->seed_pending == 0u))
    {
        return HDG_INV_SEC_SEED_KEY_BINDING;
    }

    /* SEC-3 : apres un ECUReset positif, la securite doit etre verrouillee. */
    if (positive_reset && (post->security_level != UDS_SECURITY_LOCKED))
    {
        return HDG_INV_SEC_RELOCK_ON_RESET;
    }

    /* XL-2 : un reset ne doit pas laisser une graine en attente. */
    if (positive_reset && (post->seed_pending != 0u))
    {
        return HDG_INV_XL_NO_AUTHORITY_CARRYOVER;
    }

    /*
     * SEC-4 : etat interdit — securite deverrouillee en session par
     * defaut. Un privilege ne doit jamais coexister avec la session la
     * moins privilegiee.
     */
    if ((post->session == UDS_SESSION_DEFAULT) &&
        (post->security_level != UDS_SECURITY_LOCKED))
    {
        return HDG_INV_SEC_RELOCK_ON_DEFAULT;
    }

    /*
     * SEC-5 : le compteur d'essais ne baisse que sur un deverrouillage
     * reussi ou une expiration de verrouillage. Toute autre baisse est
     * une remise a zero illegitime.
     */
    if ((post->failed_attempts < pre->failed_attempts) &&
        (positive_key == 0) &&
        (a != ACT_CLOCK_PAST_LOCKOUT) &&
        !((pre->locked_out != 0u) && (post->locked_out == 0u)))
    {
        return HDG_INV_SEC_MONOTONIC_ATTEMPTS;
    }

    return -1;
}

static void reset_ctx(uds_context_t *ctx, attacker_t *atk)
{
    uds_init(ctx);
    uds_set_did_provider(ctx, did_read, NULL);
    uds_set_dtc_provider(ctx, dtc_read, dtc_clear);
    uds_set_reset_handler(ctx, ecu_reset);
    /* Pas d'entropie : le generateur de graines reste deterministe. */
    atk->clock = 1000u;
    atk->have_last_key = 0;
    memset(atk->last_key, 0, sizeof(atk->last_key));
}

/*
 * Rejoue une sequence sur un contexte neuf. Renvoie l'ID de l'invariant
 * viole (au premier pas fautif) ou -1.
 */
static int replay(const action_t *seq, int len)
{
    uds_context_t ctx;
    attacker_t atk;
    int i;

    reset_ctx(&ctx, &atk);

    for (i = 0; i < len; i++)
    {
        uint8_t resp[64];
        uint16_t rlen = 0u;
        snap_t pre = snapshot(&ctx);
        int viol;

        apply_action(&ctx, &atk, seq[i], resp, &rlen);
        viol = check_invariants(&pre, &ctx, seq[i], resp, rlen);
        if (viol >= 0)
        {
            return viol;
        }
    }
    return -1;
}

/*
 * Minimisation par delta-debug glouton : tant qu'on peut retirer une
 * action sans perdre la violation, on la retire. Converge vers un
 * contre-exemple irreductible.
 */
static int minimize(action_t *seq, int len, int target_inv)
{
    int changed = 1;
    while (changed != 0)
    {
        int i;
        changed = 0;
        for (i = 0; i < len; i++)
        {
            action_t saved = seq[i];
            int j;
            action_t tmp[64];
            int tlen = 0;

            for (j = 0; j < len; j++)
            {
                if (j != i) { tmp[tlen++] = seq[j]; }
            }

            if (replay(tmp, tlen) == target_inv)
            {
                for (j = 0; j < tlen; j++) { seq[j] = tmp[j]; }
                len = tlen;
                changed = 1;
                i--;
            }
            else
            {
                (void)saved;
            }
        }
    }
    return len;
}

/* ------------------------------------------------------------------ */
/* Couverture d'etats                                                  */
/* ------------------------------------------------------------------ */

#define STATE_TABLE 512
static uint8_t g_seen[STATE_TABLE];
static int g_states = 0;

static void note_state(const uds_context_t *ctx)
{
    /* Empreinte compacte des dimensions de securite. */
    uint32_t h = ((uint32_t)ctx->session << 0) ^
                 ((uint32_t)ctx->security_level << 3) ^
                 ((uint32_t)ctx->seed_pending << 6) ^
                 ((uint32_t)ctx->locked_out << 7) ^
                 ((uint32_t)ctx->failed_attempts << 8);
    uint32_t k = h % STATE_TABLE;
    if (g_seen[k] == 0u) { g_seen[k] = 1u; g_states++; }
}

/* ------------------------------------------------------------------ */
/* Rapport d'un contre-exemple (§10 : explicable)                      */
/* ------------------------------------------------------------------ */

static void explain(int inv, const action_t *seq, int len)
{
    const hdg_invariant_info_t *info = hdg_invariant_info(
        (hdg_invariant_id_t)inv);
    uds_context_t ctx;
    attacker_t atk;
    int i;

    printf("\n============================================================\n");
    printf(" CONTRE-EXEMPLE  —  invariant %s viole\n",
           (info != NULL) ? info->code : "?");
    printf("============================================================\n");
    if (info != NULL)
    {
        printf(" Propriete : %s\n", info->summary);
    }
    printf(" Sequence minimale : %d action(s)\n", len);
    for (i = 0; i < len; i++)
    {
        printf("   %2d. %s\n", i + 1, action_name(seq[i]));
    }

    /* Rejoue en montrant l'etat au moment de la violation. */
    reset_ctx(&ctx, &atk);
    for (i = 0; i < len; i++)
    {
        uint8_t resp[64];
        uint16_t rlen = 0u;
        snap_t pre = snapshot(&ctx);
        int viol;

        apply_action(&ctx, &atk, seq[i], resp, &rlen);
        viol = check_invariants(&pre, &ctx, seq[i], resp, rlen);
        if (viol >= 0)
        {
            printf("\n Au pas %d (%s) :\n", i + 1, action_name(seq[i]));
            printf("   session   : %d\n", (int)ctx.session);
            printf("   securite  : %s\n",
                   (ctx.security_level == UDS_SECURITY_LOCKED)
                       ? "LOCKED" : "UNLOCKED");
            printf("   graine    : %s\n",
                   ctx.seed_pending ? "en attente" : "aucune");
            printf("   reponse   : ");
            if (rlen == 0u) { printf("(aucune)"); }
            else { unsigned j; for (j = 0; j < rlen; j++) printf("%02X ", resp[j]); }
            printf("\n   decision AHDG : DROP + RECOVER (a implementer M52+)\n");
            break;
        }
    }
    printf("============================================================\n");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    uint64_t budget = 500000u;
    uint32_t seed = 0xA11CE;
    int max_len = 14;
    uint64_t n;
    uint64_t tested = 0u;

    /* Un contre-exemple minimal par invariant, la premiere fois. */
    int found[HDG_INV_COUNT];
    int i;

    if (argc > 1) { budget = strtoull(argv[1], NULL, 10); }
    if (argc > 2) { seed = (uint32_t)strtoul(argv[2], NULL, 0); }

    for (i = 0; i < HDG_INV_COUNT; i++) { found[i] = 0; }
    g_rng = (seed != 0u) ? seed : 1u;

    printf("============================================================\n");
    printf(" AHDG — exploration adversariale de l'espace d'etats UDS\n");
    printf("============================================================\n");
    printf(" cible      : src/uds/uds.c (code de production)\n");
    printf(" sequences  : %llu\n", (unsigned long long)budget);
    printf(" graine     : 0x%08X\n", seed);
    printf(" longueur   : jusqu'a %d actions\n\n", max_len);

    for (n = 0u; n < budget; n++)
    {
        uds_context_t ctx;
        attacker_t atk;
        action_t seq[64];
        int len = (int)(rng_next() % (uint32_t)max_len) + 1;
        int step;

        reset_ctx(&ctx, &atk);
        note_state(&ctx);
        tested++;

        for (step = 0; step < len; step++)
        {
            uint8_t resp[64];
            uint16_t rlen = 0u;
            snap_t pre = snapshot(&ctx);
            action_t a = (action_t)(rng_next() % (uint32_t)ACT_COUNT);
            int viol;

            seq[step] = a;
            apply_action(&ctx, &atk, a, resp, &rlen);
            note_state(&ctx);

            viol = check_invariants(&pre, &ctx, a, resp, rlen);
            if ((viol >= 0) && (found[viol] == 0))
            {
                int mlen = minimize(seq, step + 1, viol);
                found[viol] = 1;
                explain(viol, seq, mlen);
            }
            if (viol >= 0) { break; }
        }
    }

    printf("\n============================================================\n");
    printf(" Bilan\n");
    printf("============================================================\n");
    printf(" sequences jouees    : %llu\n", (unsigned long long)tested);
    printf(" etats de securite   : %d distincts\n", g_states);
    printf("\n Par invariant :\n");
    {
        size_t count = 0u;
        const hdg_invariant_info_t *tab = hdg_invariant_table(&count);
        int total_found = 0;
        size_t k;
        for (k = 0u; k < count; k++)
        {
            int id = (int)tab[k].id;
            int hit = (id < HDG_INV_COUNT) ? found[id] : 0;
            /* On ne rapporte que les invariants reellement evalues ici. */
            switch (tab[k].id)
            {
            case HDG_INV_SEC_NO_UNAUTH_EFFECT:
            case HDG_INV_SEC_SEED_KEY_BINDING:
            case HDG_INV_SEC_RELOCK_ON_RESET:
            case HDG_INV_SEC_RELOCK_ON_DEFAULT:
            case HDG_INV_SEC_MONOTONIC_ATTEMPTS:
            case HDG_INV_XL_NO_AUTHORITY_CARRYOVER:
                printf("   %-8s %s\n", tab[k].code,
                       hit ? "CONTRE-EXEMPLE TROUVE"
                           : "aucun contre-exemple (assurance bornee)");
                if (hit != 0) { total_found++; }
                break;
            default:
                /* Non evaluable sans la couche ISO-TP : voir M51+. */
                break;
            }
        }
        printf("\n Contre-exemples : %d\n", total_found);
        printf("============================================================\n");

        /*
         * Code de sortie : 0 si aucune surprise. Un contre-exemple non
         * encore explique par un test de regression fait echouer, pour
         * que la CI le signale.
         */
        return (total_found == 0) ? 0 : 2;
    }
}
