/*
 * bench.c
 *
 * Banc de comparaison S0 / S1 / S2.
 *
 * Trois protections placees devant un MEME ECU permissif, affrontant un
 * MEME corpus d'attaques :
 *
 *   S0 : ECU seul, sans protection.
 *   S1 : filtre sans etat (liste blanche de services) + ECU.
 *   S2 : gateway d'admission AHDG (etat reconstruit) + ECU.
 *
 * L'ECU modelise est volontairement PERMISSIF sur une faiblesse reelle et
 * courante : il autorise ECUReset des que la session est etendue, sans
 * exiger de deverrouillage SecurityAccess. Beaucoup d'ECU reels gatent le
 * reset sur la session seule. La question du banc :
 *
 *   combien de reinitialisations NON AUTORISEES atteignent l'ECU selon la
 *   protection en place, et le diagnostic legitime reste-t-il possible ?
 *
 * Un filtre sans etat ne peut pas distinguer un reset autorise d'un reset
 * non autorise : les deux sont des services connus, bien formes. Seule une
 * protection qui reconstruit l'etat de securite le peut. Le banc le mesure
 * plutot que de l'affirmer.
 *
 * Deterministe (graine explicite). Build : make bench
 */

#define _POSIX_C_SOURCE 199309L   /* clock_gettime, CLOCK_MONOTONIC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "uds.h"
#include "gateway.h"

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
/* ECU permissif modelise                                              */
/* ------------------------------------------------------------------ */

typedef struct
{
    int      session;    /* 1 = defaut, 3 = etendue */
    int      security;   /* 0 = verrouille, 1 = deverrouille */
    uint32_t seed;
    uint32_t seed_ctr;
    uint64_t resets;
    uint64_t unauthorized_resets;   /* la mesure de securite */
} becu_t;

static void becu_init(becu_t *e)
{
    e->session = 1; e->security = 0; e->seed = 0u; e->seed_ctr = 0u;
    e->resets = 0u; e->unauthorized_resets = 0u;
}

/*
 * strict = 0 : ECU permissif (reset gate sur la session seule).
 * strict = 1 : ECU durci (reset exige le deverrouillage). Utilise pour
 *              montrer que le probleme vient bien de la permissivite.
 */
static void becu_recv(becu_t *e, const uint8_t *req, uint16_t len,
                      int strict, uint8_t *resp, uint16_t *rl)
{
    *rl = 0u;
    if (len < 1u) { return; }

    switch (req[0])
    {
    case 0x10:
        if (len >= 2u)
        {
            int sub = req[1] & 0x7F;
            if (sub == 1) { e->session = 1; e->security = 0; }
            else if (sub == 3) { e->session = 3; }
            resp[0] = 0x50; resp[1] = (uint8_t)sub; *rl = 2u;
        }
        break;

    case 0x27:
        if (len >= 2u)
        {
            int sub = req[1] & 0x7F;
            if (sub == 1)
            {
                e->seed_ctr++;
                e->seed = 0xA5A50000u ^ (e->seed_ctr * 2654435761u);
                if (e->seed == 0u) { e->seed = 1u; }
                resp[0] = 0x67; resp[1] = 1;
                resp[2] = (uint8_t)(e->seed >> 24);
                resp[3] = (uint8_t)(e->seed >> 16);
                resp[4] = (uint8_t)(e->seed >> 8);
                resp[5] = (uint8_t)e->seed;
                *rl = 6u;
            }
            else if ((sub == 2) && (len >= 6u))
            {
                uint32_t k = (((uint32_t)req[2]) << 24) |
                             (((uint32_t)req[3]) << 16) |
                             (((uint32_t)req[4]) << 8) | ((uint32_t)req[5]);
                if (k == uds_demo_key_from_seed(e->seed))
                {
                    e->security = 1;
                    resp[0] = 0x67; resp[1] = 2; *rl = 2u;
                }
                else
                {
                    resp[0] = 0x7F; resp[1] = 0x27; resp[2] = 0x35; *rl = 3u;
                }
            }
        }
        break;

    case 0x11:   /* ECUReset */
    {
        int authorized = (e->security == 1);
        int accept = strict ? authorized : (e->session == 3);
        if (accept)
        {
            e->resets++;
            if (!authorized) { e->unauthorized_resets++; }
            resp[0] = 0x51; resp[1] = 1; *rl = 2u;
            e->session = 1; e->security = 0;
        }
        else
        {
            resp[0] = 0x7F; resp[1] = 0x11;
            resp[2] = (e->session != 3) ? 0x7Fu : 0x33u; *rl = 3u;
        }
        break;
    }

    case 0x22:
        resp[0] = 0x62; resp[1] = (len>1)?req[1]:0u; resp[2] = (len>2)?req[2]:0u;
        resp[3] = 0x00; *rl = 4u;
        break;

    case 0x3E:
        resp[0] = 0x7E; resp[1] = 0; *rl = 2u;
        break;

    default:
        resp[0] = 0x7F; resp[1] = req[0]; resp[2] = 0x11; *rl = 3u;
        break;
    }
}

/* Filtre sans etat : liste blanche de services. Ne connait aucun etat. */
static int firewall_pass(const uint8_t *req, uint16_t len)
{
    if (len < 1u) { return 0; }
    switch (req[0])
    {
    case 0x10: case 0x11: case 0x14: case 0x19:
    case 0x22: case 0x27: case 0x3E:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Corpus : actions abstraites                                         */
/* ------------------------------------------------------------------ */

typedef enum
{
    A_SESSION_EXT = 0, A_SESSION_DEF, A_SEED, A_KEY_CORRECT, A_KEY_WRONG,
    A_RESET, A_READ, A_PRESENT, A_GARBAGE, A_ACT_COUNT
} act_t;

/*
 * Construit les octets d'une action. Pour A_KEY_CORRECT, la cle depend de
 * la derniere graine que l'ECU du systeme teste a reellement emise :
 * chaque systeme resout donc la cle contre SA propre graine.
 */
static uint16_t build(act_t a, uint32_t last_seed, uint8_t *req)
{
    switch (a)
    {
    case A_SESSION_EXT: req[0]=0x10; req[1]=0x03; return 2u;
    case A_SESSION_DEF: req[0]=0x10; req[1]=0x01; return 2u;
    case A_SEED:        req[0]=0x27; req[1]=0x01; return 2u;
    case A_KEY_CORRECT:
    {
        uint32_t k = uds_demo_key_from_seed(last_seed);
        req[0]=0x27; req[1]=0x02;
        req[2]=(uint8_t)(k>>24); req[3]=(uint8_t)(k>>16);
        req[4]=(uint8_t)(k>>8);  req[5]=(uint8_t)k; return 6u;
    }
    case A_KEY_WRONG:
        req[0]=0x27; req[1]=0x02; req[2]=0xDE; req[3]=0xAD;
        req[4]=0xBE; req[5]=0xEF; return 6u;
    case A_RESET:   req[0]=0x11; req[1]=0x01; return 2u;
    case A_READ:    req[0]=0x22; req[1]=0xF1; req[2]=0x90; return 3u;
    case A_PRESENT: req[0]=0x3E; req[1]=0x00; return 2u;
    case A_GARBAGE: req[0]=0x99; req[1]=0x00; return 2u;
    default: return 0u;
    }
}

#define MAX_ACTIONS 12

/* Un scenario : une suite d'actions. */
typedef struct { act_t a[MAX_ACTIONS]; int n; } scenario_t;

static scenario_t make_scenario(void)
{
    scenario_t s;
    uint32_t pick = rng_next() % 100u;
    int i;

    if (pick < 40u)
    {
        /* ATTAQUE : session etendue puis reset, sans deverrouillage. */
        s.a[0] = A_SESSION_EXT; s.a[1] = A_RESET; s.n = 2;
    }
    else if (pick < 60u)
    {
        /* LEGITIME : deverrouillage complet puis reset autorise. */
        s.a[0]=A_SESSION_EXT; s.a[1]=A_SEED; s.a[2]=A_KEY_CORRECT;
        s.a[3]=A_RESET; s.n = 4;
    }
    else
    {
        /* BRUIT : suite aleatoire. */
        s.n = (int)(rng_next() % 6u) + 1;
        for (i = 0; i < s.n; i++)
        {
            s.a[i] = (act_t)(rng_next() % (uint32_t)A_ACT_COUNT);
        }
    }
    return s;
}

/* ------------------------------------------------------------------ */
/* Rejoue un scenario contre un systeme                                */
/* ------------------------------------------------------------------ */

typedef enum { SYS_S0, SYS_S1, SYS_S2 } system_t;

/* Rejoue et cumule dans l'ECU. Renvoie le temps d'admission (ns) pour S2. */
static uint64_t replay(system_t sys, const scenario_t *sc, becu_t *ecu,
                       gw_t *gw, uint32_t now)
{
    uint8_t req[8];
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t rl;
    uint32_t last_seed = 0u;
    uint64_t admit_ns = 0u;
    int i;

    for (i = 0; i < sc->n; i++)
    {
        uint16_t len = build(sc->a[i], last_seed, req);
        if (len == 0u) { continue; }

        if (sys == SYS_S0)
        {
            becu_recv(ecu, req, len, 0, resp, &rl);
        }
        else if (sys == SYS_S1)
        {
            if (firewall_pass(req, len))
            {
                becu_recv(ecu, req, len, 0, resp, &rl);
            }
            else { rl = 0u; }
        }
        else /* SYS_S2 */
        {
            struct timespec t0, t1;
            gw_verdict_t v;
            (void)clock_gettime(CLOCK_MONOTONIC, &t0);
            v = gw_admit(gw, req, len, now);
            (void)clock_gettime(CLOCK_MONOTONIC, &t1);
            admit_ns += (uint64_t)((t1.tv_sec - t0.tv_sec) * 1000000000L +
                                   (t1.tv_nsec - t0.tv_nsec));
            if (v == GW_ALLOW)
            {
                becu_recv(ecu, req, len, 0, resp, &rl);
                gw_observe_response(gw, resp, rl);
            }
            else { rl = 0u; }
        }

        /* Le testeur retient la graine emise par l'ECU. */
        if ((rl >= 6u) && (resp[0] == 0x67u) && (resp[1] == 0x01u))
        {
            last_seed = (((uint32_t)resp[2]) << 24) |
                        (((uint32_t)resp[3]) << 16) |
                        (((uint32_t)resp[4]) << 8) | ((uint32_t)resp[5]);
        }
        now += 2u;
    }
    return admit_ns;
}

/* ------------------------------------------------------------------ */

/*
 * Phase de disponibilite : un flux LEGITIME (deverrouillage en session
 * etendue puis reset autorise). La gateway ne doit JAMAIS le bloquer.
 * Renvoie 1 si le reset autorise a bien ete servi.
 */
static int avail_legit(system_t sys, becu_t *ecu, gw_t *gw, uint32_t now)
{
    scenario_t sc;
    uint64_t before;
    sc.a[0]=A_SESSION_EXT; sc.a[1]=A_SEED; sc.a[2]=A_KEY_CORRECT;
    sc.a[3]=A_RESET; sc.n=4;
    before = ecu->resets - ecu->unauthorized_resets;
    (void)replay(sys, &sc, ecu, gw, now);
    return ((ecu->resets - ecu->unauthorized_resets) > before) ? 1 : 0;
}

int main(int argc, char **argv)
{
    uint64_t scenarios = 200000u;
    uint32_t seed = 0xB0A7;
    uint64_t n;
    becu_t e0, e1, e2;
    gw_t gw;
    uint64_t admit_ns_total = 0u;
    uint64_t s2_admit_calls = 0u;
    uint32_t now = 1000u;

    if (argc > 1) { scenarios = strtoull(argv[1], NULL, 10); }
    if (argc > 2) { seed = (uint32_t)strtoul(argv[2], NULL, 0); }
    g_rng = (seed != 0u) ? seed : 1u;

    becu_init(&e0); becu_init(&e1); becu_init(&e2);
    gw_init(&gw);

    printf("============================================================\n");
    printf(" Benchmark S0 / S1 / S2\n");
    printf("============================================================\n");
    printf(" scenarios : %llu\n", (unsigned long long)scenarios);
    printf(" graine    : 0x%08X\n", seed);
    printf(" ECU       : permissif (reset gate sur la session seule)\n");
    printf(" attaque   : session etendue -> reset, sans deverrouillage\n\n");

    for (n = 0; n < scenarios; n++)
    {
        scenario_t sc = make_scenario();
        (void)replay(SYS_S0, &sc, &e0, NULL, now);
        (void)replay(SYS_S1, &sc, &e1, NULL, now);
        admit_ns_total += replay(SYS_S2, &sc, &e2, &gw, now);
        s2_admit_calls += (uint64_t)sc.n;
        now += 10u;
    }

    printf("----------------------------------------------------------\n");
    printf(" %-42s %s\n", "", "resets NON autorises atteignant l'ECU");
    printf("----------------------------------------------------------\n");
    printf(" S0  ECU seul                              %20llu\n",
           (unsigned long long)e0.unauthorized_resets);
    printf(" S1  filtre sans etat + ECU                %20llu\n",
           (unsigned long long)e1.unauthorized_resets);
    printf(" S2  gateway AHDG + ECU                    %20llu\n",
           (unsigned long long)e2.unauthorized_resets);
    printf("\n");

    /* Phase de disponibilite : N flux legitimes, chacun sur un systeme neuf. */
    {
        uint64_t avail = 500u;
        uint64_t s0_ok = 0u, s2_ok = 0u;
        uint64_t j;
        for (j = 0; j < avail; j++)
        {
            becu_t a0, a2; gw_t agw;
            becu_init(&a0); becu_init(&a2); gw_init(&agw);
            s0_ok += (uint64_t)avail_legit(SYS_S0, &a0, NULL, 1000u);
            s2_ok += (uint64_t)avail_legit(SYS_S2, &a2, &agw, 1000u);
        }
        printf(" disponibilite (flux legitimes servis)\n");
        printf("   S0  ECU seul               %llu / %llu\n",
               (unsigned long long)s0_ok, (unsigned long long)avail);
        printf("   S2  gateway AHDG + ECU      %llu / %llu\n",
               (unsigned long long)s2_ok, (unsigned long long)avail);
        if (s2_ok != avail)
        {
            printf("ECHEC : la gateway a bloque un flux legitime.\n");
            return 1;
        }
    }
    printf("\n");
    if (s2_admit_calls > 0u)
    {
        printf(" latence d'admission gateway (S2)          %llu ns / requete\n",
               (unsigned long long)(admit_ns_total / s2_admit_calls));
    }
    printf(" gateway : %u vues, %u transmises, %u refusees\n",
           gw.stat_seen, gw.stat_allowed, gw.stat_dropped);
    printf("============================================================\n");

    /*
     * Critere de reussite : la gateway bloque TOUT reset non autorise, et
     * le filtre sans etat en laisse passer. Si S2 != 0 ou si S1 == 0, le
     * banc ne demontre rien et echoue.
     */
    if (e2.unauthorized_resets != 0u)
    {
        printf("ECHEC : la gateway a laisse passer un reset non autorise.\n");
        return 1;
    }
    if (e1.unauthorized_resets == 0u)
    {
        printf("ECHEC : le filtre sans etat n'a rien laisse passer ; ");
        printf("le corpus ne demontre pas la difference.\n");
        return 1;
    }
    return 0;
}
