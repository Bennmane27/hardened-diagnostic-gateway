/*
 * ahdg_wasm.c
 *
 * Point d'entree WebAssembly du simulateur AHDG en ligne.
 *
 * Compile le VRAI stack (uds.c, isotp.c, ecu_data.c) plus l'explorateur
 * adversarial vers WebAssembly, pour qu'un visiteur puisse tout tester
 * dans son navigateur, sans aucun environnement local. Ce qui tourne dans
 * la page est le code de production, pas une reimplementation JavaScript.
 *
 * Ce fichier vit dans web/, hors de src/ : il peut donc utiliser des
 * tampons statiques de retour sans enfreindre l'invariant I2 qui ne
 * concerne que src/. Aucun malloc : les fonctions renvoient un pointeur
 * vers un tampon statique que le JavaScript lit via UTF8ToString.
 *
 * Build : web/build.sh (emscripten) ou la CI GitHub Pages.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "uds.h"
#include "isotp.h"
#include "ecu_data.h"
#include "invariants.h"
#include "ahdg_explore_core.h"
#include "gateway.h"
#include "bench_core.h"

/* EMSCRIPTEN_KEEPALIVE marque les fonctions a exporter. Hors emscripten
 * (verification avec gcc), on le neutralise pour que le fichier compile. */
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define AHDG_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define AHDG_EXPORT
#endif

/* Tampons de retour statiques : une seule valeur vit a la fois par usage. */
static char  g_json[8192];
static char  g_state[512];   /* tampon distinct : evite l'aliasing avec g_json */
static char  g_hex[512];

/* Contexte ECU persistant entre les appels du navigateur. */
static uds_context_t g_uds;
static ecu_data_t    g_data;
static uint32_t      g_clock = 1000u;
static int           g_ready = 0;

/* ------------------------------------------------------------------ */
/* Utilitaires                                                         */
/* ------------------------------------------------------------------ */

static int hex_nibble(char c)
{
    if ((c >= '0') && (c <= '9')) { return c - '0'; }
    if ((c >= 'a') && (c <= 'f')) { return (c - 'a') + 10; }
    if ((c >= 'A') && (c <= 'F')) { return (c - 'A') + 10; }
    return -1;
}

/* Parse une chaine hexa (espaces ignores) en octets. Renvoie la longueur. */
static uint16_t parse_hex(const char *s, uint8_t *out, uint16_t cap)
{
    uint16_t n = 0u;
    int hi = -1;

    while ((*s != '\0') && (n < cap))
    {
        int v = hex_nibble(*s);
        if (v >= 0)
        {
            if (hi < 0) { hi = v; }
            else { out[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
        }
        s++;
    }
    return n;
}

static void bytes_to_hex(const uint8_t *b, uint16_t n, char *out, size_t cap)
{
    size_t p = 0u;
    uint16_t i;
    for (i = 0u; (i < n) && (p + 3u < cap); i++)
    {
        int w = snprintf(&out[p], cap - p, "%02X ", b[i]);
        if (w <= 0) { break; }
        p += (size_t)w;
    }
    if (p > 0u) { out[p - 1u] = '\0'; } else { out[0] = '\0'; }
}

static void ensure_ready(void)
{
    if (g_ready == 0)
    {
        ecu_data_init(&g_data);
        uds_init(&g_uds);
        uds_set_did_provider(&g_uds, ecu_data_read_did, &g_data);
        uds_set_dtc_provider(&g_uds, ecu_data_read_dtc, ecu_data_clear_dtc);
        uds_set_reset_handler(&g_uds, ecu_data_reset);
        g_clock = 1000u;
        g_ready = 1;
    }
}

static const char *state_json(void)
{
    snprintf(g_state, sizeof(g_state),
             "{\"session\":%d,\"session_name\":\"%s\","
             "\"security\":%d,\"security_name\":\"%s\","
             "\"seed_pending\":%d,\"failed_attempts\":%d,\"locked_out\":%d}",
             (int)g_uds.session, uds_session_to_string(g_uds.session),
             (int)g_uds.security_level,
             (g_uds.security_level == UDS_SECURITY_LOCKED) ? "LOCKED"
                                                           : "UNLOCKED",
             (int)g_uds.seed_pending, (int)g_uds.failed_attempts,
             (int)g_uds.locked_out);
    return g_state;
}

/* ------------------------------------------------------------------ */
/* API exportee                                                        */
/* ------------------------------------------------------------------ */

AHDG_EXPORT const char *ahdg_version(void)
{
    return "AHDG WASM 1.0 (uds+isotp+ecu, real code)";
}

AHDG_EXPORT const char *ahdg_reset(void)
{
    g_ready = 0;
    ensure_ready();
    return state_json();
}

AHDG_EXPORT const char *ahdg_state(void)
{
    ensure_ready();
    return state_json();
}

/*
 * Traite une requete UDS brute (hexa) au niveau APPLICATION, sur le vrai
 * serveur, avec le contexte persistant. Renvoie la reponse, l'etat, et le
 * verdict d'invariant (le futur moteur de gateway s'appuiera dessus).
 */
AHDG_EXPORT const char *ahdg_request(const char *hex)
{
    uint8_t req[64];
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t req_len;
    uint16_t resp_len = 0u;
    char resp_hex[512];
    ahdg_snap_t pre;
    uds_result_t r;
    int viol;

    ensure_ready();
    req_len = parse_hex(hex, req, sizeof(req));

    pre = ahdg_snapshot(&g_uds);
    r = uds_handle_request(&g_uds, req, req_len, g_clock,
                           resp, (uint16_t)sizeof(resp), &resp_len);
    g_clock += 5u;

    bytes_to_hex(resp, resp_len, resp_hex, sizeof(resp_hex));

    /* Verdict d'invariant : l'attaquant et la gateway partagent le meme. */
    viol = -1;
    if (r == UDS_OK)
    {
        viol = ahdg_check(&pre, &g_uds, AHDG_READ_DID /* action neutre */,
                          resp, resp_len);
    }

    snprintf(g_json, sizeof(g_json),
             "{\"result\":%d,\"result_name\":\"%s\","
             "\"response\":\"%s\",\"response_len\":%d,"
             "\"verdict\":\"%s\",\"invariant\":\"%s\","
             "\"state\":%s}",
             (int)r, uds_result_to_string(r),
             resp_hex, (int)resp_len,
             (viol >= 0) ? "DROP" : "ALLOW",
             (viol >= 0) ? hdg_invariant_code((hdg_invariant_id_t)viol) : "",
             state_json());
    return g_json;
}

/* Decode une trame ISO-TP isolee (hexa) et decrit ses champs. */
AHDG_EXPORT const char *ahdg_isotp_decode(const char *hex)
{
    uint8_t frame[8];
    uint16_t n = parse_hex(hex, frame, sizeof(frame));
    isotp_frame_type_t type;
    isotp_result_t res;

    if (n == 0u)
    {
        snprintf(g_json, sizeof(g_json),
                 "{\"ok\":false,\"reason\":\"trame vide\"}");
        return g_json;
    }

    res = isotp_get_frame_type(frame, (uint8_t)n, &type);
    if (res != ISOTP_OK)
    {
        snprintf(g_json, sizeof(g_json),
                 "{\"ok\":false,\"reason\":\"%s\"}",
                 isotp_result_to_string(res));
        return g_json;
    }

    if (type == ISOTP_FRAME_SINGLE)
    {
        const uint8_t *payload = NULL;
        uint8_t plen = 0u;
        res = isotp_decode_single_frame(frame, (uint8_t)n, &payload, &plen);
        if (res == ISOTP_OK)
        {
            char ph[64];
            bytes_to_hex(payload, plen, ph, sizeof(ph));
            snprintf(g_json, sizeof(g_json),
                     "{\"ok\":true,\"type\":\"Single Frame\","
                     "\"length\":%d,\"payload\":\"%s\"}", (int)plen, ph);
        }
        else
        {
            snprintf(g_json, sizeof(g_json),
                     "{\"ok\":false,\"type\":\"Single Frame\","
                     "\"reason\":\"%s\"}", isotp_result_to_string(res));
        }
        return g_json;
    }

    snprintf(g_json, sizeof(g_json),
             "{\"ok\":true,\"type\":\"%s\"}",
             isotp_frame_type_to_string(type));
    return g_json;
}

/*
 * Lance l'explorateur adversarial dans le navigateur. Renvoie le bilan et,
 * pour chaque invariant viole, la sequence minimale reproductible.
 */
AHDG_EXPORT const char *ahdg_explore(int budget, unsigned int seed)
{
    ahdg_results_t res;
    size_t p;
    int i;
    int first = 1;

    if (budget < 1) { budget = 1; }
    if (budget > 5000000) { budget = 5000000; }

    ahdg_run((uint64_t)budget, (uint32_t)seed, 14, &res);

    p = (size_t)snprintf(g_json, sizeof(g_json),
                         "{\"tested\":%llu,\"states\":%d,"
                         "\"counterexamples\":[",
                         (unsigned long long)res.tested, res.states);

    for (i = 0; i < AHDG_EVALUATED_COUNT; i++)
    {
        int id = AHDG_EVALUATED[i];
        const hdg_invariant_info_t *info;
        int k;

        if (res.found[id] == 0) { continue; }
        info = hdg_invariant_info((hdg_invariant_id_t)id);

        p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p,
                              "%s{\"code\":\"%s\",\"summary\":\"%s\","
                              "\"actions\":[",
                              first ? "" : ",",
                              (info != NULL) ? info->code : "?",
                              (info != NULL) ? info->summary : "");
        first = 0;
        for (k = 0; k < res.cex_len[id]; k++)
        {
            p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p,
                                  "%s\"%s\"", (k == 0) ? "" : ",",
                                  ahdg_action_name(res.cex[id][k]));
        }
        p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p, "]}");
    }

    /* Liste des invariants evalues, pour l'affichage "assurance bornee". */
    p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p,
                          "],\"evaluated\":[");
    for (i = 0; i < AHDG_EVALUATED_COUNT; i++)
    {
        int id = AHDG_EVALUATED[i];
        const hdg_invariant_info_t *info =
            hdg_invariant_info((hdg_invariant_id_t)id);
        p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p,
                              "%s{\"code\":\"%s\",\"found\":%s}",
                              (i == 0) ? "" : ",",
                              (info != NULL) ? info->code : "?",
                              res.found[id] ? "true" : "false");
    }
    (void)snprintf(&g_json[p], sizeof(g_json) - p, "]}");

    return g_json;
}

/* Catalogue des invariants, pour l'affichage. */
AHDG_EXPORT const char *ahdg_invariants(void)
{
    size_t count = 0u;
    const hdg_invariant_info_t *tab = hdg_invariant_table(&count);
    size_t p = 0u;
    size_t i;

    p += (size_t)snprintf(g_json, sizeof(g_json), "[");
    for (i = 0u; i < count; i++)
    {
        p += (size_t)snprintf(&g_json[p], sizeof(g_json) - p,
                              "%s{\"code\":\"%s\",\"summary\":\"%s\"}",
                              (i == 0u) ? "" : ",",
                              tab[i].code, tab[i].summary);
    }
    (void)snprintf(&g_json[p], sizeof(g_json) - p, "]");
    return g_json;
}


/*
 * Lance le benchmark S0 / S1 / S2 dans le navigateur : le meme code que
 * bench/bench.c (via bench_core.h). Renvoie les compteurs.
 */
AHDG_EXPORT const char *ahdg_benchmark(int scenarios, unsigned int seed)
{
    bench_results_t r;

    if (scenarios < 1) { scenarios = 1; }
    if (scenarios > 2000000) { scenarios = 2000000; }

    bench_run((uint64_t)scenarios, (uint32_t)seed, 500u, &r);

    snprintf(g_json, sizeof(g_json),
             "{\"scenarios\":%llu,"
             "\"s0\":%llu,\"s1\":%llu,\"s2\":%llu,"
             "\"avail_total\":%llu,\"s0_avail\":%llu,\"s2_avail\":%llu,"
             "\"gw_seen\":%u,\"gw_allowed\":%u,\"gw_dropped\":%u}",
             (unsigned long long)r.scenarios,
             (unsigned long long)r.s0_unauth,
             (unsigned long long)r.s1_unauth,
             (unsigned long long)r.s2_unauth,
             (unsigned long long)r.avail_total,
             (unsigned long long)r.s0_avail,
             (unsigned long long)r.s2_avail,
             r.gw_seen, r.gw_allowed, r.gw_dropped);
    return g_json;
}

/* Encode une payload UDS (hexa) en Single Frame ISO-TP, pour l'inspecteur. */
AHDG_EXPORT const char *ahdg_isotp_encode(const char *hex)
{
    uint8_t payload[8];
    uint8_t frame[8];
    uint8_t out_len = 0u;
    uint16_t n = parse_hex(hex, payload, sizeof(payload));
    isotp_result_t res;

    if ((n == 0u) || (n > ISOTP_SF_MAX_PAYLOAD))
    {
        snprintf(g_hex, sizeof(g_hex), "(1 a 7 octets requis)");
        return g_hex;
    }

    res = isotp_encode_single_frame(payload, (uint8_t)n, frame,
                                    (uint8_t)sizeof(frame), &out_len);
    if (res != ISOTP_OK)
    {
        snprintf(g_hex, sizeof(g_hex), "(%s)", isotp_result_to_string(res));
        return g_hex;
    }
    bytes_to_hex(frame, out_len, g_hex, sizeof(g_hex));
    return g_hex;
}
