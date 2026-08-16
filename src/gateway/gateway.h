/*
 * gateway.h
 *
 * Gateway d'admission AHDG.
 *
 * La passerelle se place entre le testeur et l'ECU et decide, pour chaque
 * requete de diagnostic, si elle a le droit d'atteindre l'ECU. Elle
 * reconstruit l'etat de securite en observant le trafic dans les DEUX
 * sens (requetes du testeur, reponses de l'ECU), et refuse toute requete
 * que la politique durcie n'accepterait pas.
 *
 * Idee cle : la politique EST le serveur UDS durci de src/uds, reutilise
 * comme controleur d'admission. La passerelle fait tourner un serveur
 * "fantome" (shadow) synchronise sur l'ECU ; une requete n'est transmise
 * que si le serveur durci l'accepterait. Un ECU plus permissif place
 * derriere la passerelle herite ainsi de la politique durcie, ce qu'un
 * filtre sans etat ne peut pas offrir.
 *
 * Comme les couches isotp et uds, ce module n'inclut aucun header systeme
 * (invariant I1) : il doit rester portable vers un microcontroleur.
 */

#ifndef HDG_GATEWAY_H
#define HDG_GATEWAY_H

#include <stdint.h>

#include "uds.h"
#include "invariants.h"

typedef enum
{
    GW_ALLOW = 0,   /* transmettre la requete a l'ECU */
    GW_DROP         /* refuser : l'ECU ne verra rien   */
} gw_verdict_t;

typedef struct
{
    /* Serveur durci fantome, synchronise sur l'ECU : c'est la politique. */
    uds_context_t shadow;

    uint32_t stat_seen;
    uint32_t stat_allowed;
    uint32_t stat_dropped;

    /* Invariant du dernier refus (ou -1), pour l'explicabilite. */
    int last_invariant;
    uint8_t last_nrc;
} gw_t;

/* Etat initial : session par defaut, securite verrouillee. */
void gw_init(gw_t *gw);

/*
 * Decide si une requete UDS peut atteindre l'ECU.
 *
 * now_ms : horloge monotone, pour les temporisations de session.
 *
 * La passerelle refuse une requete lorsque la politique durcie la
 * rejetterait pour une raison d'ACCES : service protege sans
 * deverrouillage, ou service interdit dans la session courante. Les
 * autres refus (identifiant inconnu, service non implemente) relevent de
 * l'ECU et sont transmis.
 */
gw_verdict_t gw_admit(gw_t *gw, const uint8_t *request, uint16_t len,
                      uint32_t now_ms);

/*
 * Observe une reponse de l'ECU pour garder le fantome synchronise.
 *
 * Le cas essentiel : la graine de SecurityAccess. La passerelle doit
 * valider la cle du testeur contre la graine que l'ECU a reellement
 * emise, pas contre une graine qu'elle aurait generee elle-meme. Sans
 * cette observation, un deverrouillage legitime serait refuse a tort.
 */
void gw_observe_response(gw_t *gw, const uint8_t *response, uint16_t len);

/* Libelle du dernier refus, pour les traces. */
const char *gw_last_reason(const gw_t *gw);

#endif /* HDG_GATEWAY_H */
