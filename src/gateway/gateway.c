/*
 * gateway.c
 *
 * Gateway d'admission AHDG : le serveur UDS durci reutilise comme
 * controleur d'acces en amont de l'ECU.
 */

#include "gateway.h"

/* ------------------------------------------------------------------ */
/* Fournisseurs du fantome                                             */
/*                                                                     */
/* Le fantome n'a pas besoin des vraies donnees du vehicule : il ne    */
/* sert qu'a suivre l'etat de securite et de session. Ces fournisseurs */
/* renvoient des reponses positives neutres pour que la decision       */
/* d'admission ne depende jamais du CONTENU d'une lecture, seulement de */
/* son AUTORISATION.                                                    */
/* ------------------------------------------------------------------ */

static uds_result_t shadow_did(uint16_t did, uint8_t *out, uint16_t cap,
                               uint16_t *len, void *ctx)
{
    (void)did; (void)ctx;
    if (cap < 1u) { return UDS_ERR_BUFFER_TOO_SMALL; }
    out[0] = 0x00u;
    *len = 1u;
    return UDS_OK;
}

static uds_result_t shadow_dtc_read(uint8_t mask, uint8_t *out, uint16_t cap,
                                    uint16_t *len, void *ctx)
{
    (void)mask; (void)out; (void)cap; (void)ctx;
    *len = 0u;
    return UDS_OK;
}

static uds_result_t shadow_dtc_clear(uint32_t group, void *ctx)
{
    (void)group; (void)ctx;
    return UDS_OK;
}

static uds_result_t shadow_reset(uint8_t type, void *ctx)
{
    (void)type; (void)ctx;
    return UDS_OK;
}

/* ------------------------------------------------------------------ */

void gw_init(gw_t *gw)
{
    if (gw == NULL) { return; }

    uds_init(&gw->shadow);
    uds_set_did_provider(&gw->shadow, shadow_did, NULL);
    uds_set_dtc_provider(&gw->shadow, shadow_dtc_read, shadow_dtc_clear);
    uds_set_reset_handler(&gw->shadow, shadow_reset);

    gw->stat_seen      = 0u;
    gw->stat_allowed   = 0u;
    gw->stat_dropped   = 0u;
    gw->last_invariant = -1;
    gw->last_nrc       = 0u;
}

gw_verdict_t gw_admit(gw_t *gw, const uint8_t *request, uint16_t len,
                      uint32_t now_ms)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t rl = 0u;
    uds_result_t r;

    if ((gw == NULL) || (request == NULL))
    {
        return GW_DROP;
    }

    gw->stat_seen++;

    /*
     * Faire passer la requete par le serveur durci fantome. Cela met a
     * jour l'etat (session, securite) ET produit la reponse que la
     * politique durcie donnerait.
     */
    r = uds_handle_request(&gw->shadow, request, len, now_ms,
                           resp, (uint16_t)sizeof(resp), &rl);

    /*
     * Refus d'ACCES : la politique durcie repond negativement pour une
     * raison de securite ou de session. Ce sont exactement les requetes
     * qu'un ECU permissif accepterait a tort et que la passerelle doit
     * arreter.
     */
    if ((r == UDS_OK) && (rl == UDS_NEGATIVE_RESPONSE_LEN) &&
        (resp[0] == UDS_NEGATIVE_RESPONSE_SID))
    {
        uint8_t nrc = resp[2];

        if ((nrc == UDS_NRC_SECURITY_ACCESS_DENIED) ||
            (nrc == UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION) ||
            (nrc == UDS_NRC_INVALID_KEY) ||
            (nrc == UDS_NRC_EXCEED_NUMBER_OF_ATTEMPTS) ||
            (nrc == UDS_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED))
        {
            gw->stat_dropped++;
            gw->last_nrc = nrc;
            gw->last_invariant =
                (nrc == UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION)
                    ? HDG_INV_SEC_RELOCK_ON_DEFAULT
                    : HDG_INV_SEC_NO_UNAUTH_EFFECT;
            return GW_DROP;
        }
    }

    gw->stat_allowed++;
    return GW_ALLOW;
}

void gw_observe_response(gw_t *gw, const uint8_t *response, uint16_t len)
{
    if ((gw == NULL) || (response == NULL))
    {
        return;
    }

    /*
     * Reponse a une demande de graine : 67 01 <graine sur 4 octets>.
     * On aligne le fantome sur la graine reellement emise par l'ECU, afin
     * que la cle du testeur (calculee sur cette graine) valide correctement
     * dans le fantome au prochain 27 02.
     */
    if ((len >= 6u) &&
        (response[0] == (UDS_SID_SECURITY_ACCESS +
                         UDS_POSITIVE_RESPONSE_OFFSET)) &&
        (response[1] == UDS_SECURITY_REQUEST_SEED))
    {
        uint32_t seed = (((uint32_t)response[2]) << 24) |
                        (((uint32_t)response[3]) << 16) |
                        (((uint32_t)response[4]) << 8)  |
                        ((uint32_t)response[5]);

        /* Graine nulle = deja deverrouille cote ECU : rien a aligner. */
        if (seed != 0u)
        {
            gw->shadow.current_seed = seed;
            gw->shadow.seed_pending = 1u;
        }
    }
}

const char *gw_last_reason(const gw_t *gw)
{
    if ((gw == NULL) || (gw->last_invariant < 0))
    {
        return "aucun refus";
    }
    return uds_nrc_to_string(gw->last_nrc);
}
