/*
 * invariants.h
 *
 * Catalogue des invariants de securite cross-layer appliques par la
 * passerelle durcie. Voir docs/RESEARCH.md pour le modele complet.
 *
 * Ce fichier est PARTAGE entre trois consommateurs :
 *   - le moteur d'invariants (src/gateway/engine.c), qui les evalue ;
 *   - le fuzzer adversarial (fuzz/fuzz_state.c), qui cherche a les violer ;
 *   - le banc de comparaison (bench/), qui compte les violations atteignant
 *     l'ECU selon la protection en place.
 *
 * Un identifiant d'invariant est donc un CONTRAT commun : le fuzzer et le
 * moteur doivent parler exactement du meme ensemble, sinon une violation
 * decouverte par l'un serait invisible a l'autre.
 *
 * Comme les couches isotp et uds, ce fichier n'inclut aucun header systeme
 * (invariant I1) : la passerelle doit rester portable vers un microcontroleur.
 */

#ifndef HDG_INVARIANTS_H
#define HDG_INVARIANTS_H

#include <stdint.h>
#include <stddef.h>   /* NULL */

/* ------------------------------------------------------------------ */
/* Identifiants                                                        */
/*                                                                     */
/* L'ordre est stable : un identifiant ne doit jamais etre reaffecte,  */
/* car les corpus de contre-exemples enregistres y font reference.     */
/* ------------------------------------------------------------------ */

typedef enum
{
    /* -- SEC : autorite -------------------------------------------- */
    HDG_INV_SEC_NO_UNAUTH_EFFECT = 0,  /* service protege sans deverrouillage */
    HDG_INV_SEC_SEED_KEY_BINDING,      /* cle acceptee sans graine liee       */
    HDG_INV_SEC_RELOCK_ON_RESET,       /* securite non reverrouillee au reset  */
    HDG_INV_SEC_RELOCK_ON_DEFAULT,     /* securite tenue en session par defaut */
    HDG_INV_SEC_MONOTONIC_ATTEMPTS,    /* compteur d'essais efface par transport*/

    /* -- XL : cross-layer, coeur de la contribution ---------------- */
    HDG_INV_XL_TRANSPORT_CANNOT_FORGE_AUTHORITY,
    HDG_INV_XL_NO_AUTHORITY_CARRYOVER, /* autorite survivant a un abort         */
    HDG_INV_XL_EPOCH_CONSISTENCY,      /* passerelle et ECU en desaccord d'epoque*/
    HDG_INV_XL_SINGLE_WRITER,          /* deux transferts entrelaces delivres    */

    /* -- TP : integrite transport ---------------------------------- */
    HDG_INV_TP_LENGTH_HONESTY,         /* longueur delivree != longueur annoncee */
    HDG_INV_TP_SEQUENCE_MONOTONIC,     /* numero de sequence non successeur       */
    HDG_INV_TP_BOUNDED_BUFFER,         /* depassement du tampon de reassemblage   */

    /* -- TIME : temporisations ------------------------------------- */
    HDG_INV_TIME_DEADLINE_CONSISTENCY, /* N_Cr/N_Bs/S3 divergents passerelle/ECU */
    HDG_INV_TIME_NO_STALE_RESUME,      /* trame tardive relancant un transfert    */

    /* -- AVAIL : disponibilite, cible d'un deni de service --------- */
    HDG_INV_AVAIL_RECOVERABLE,         /* session valide impossible apres attaque */
    HDG_INV_AVAIL_NO_WEDGED_CONTEXT,   /* ECU laisse incapable de servir          */

    HDG_INV_COUNT                      /* sentinelle : nombre d'invariants        */
} hdg_invariant_id_t;

/* ------------------------------------------------------------------ */
/* Severite                                                            */
/*                                                                     */
/* Determine le verdict par defaut du moteur quand un invariant est    */
/* menace ; l'implementation peut affiner selon le contexte.           */
/* ------------------------------------------------------------------ */

typedef enum
{
    HDG_SEV_INFO = 0,   /* trace seulement                                   */
    HDG_SEV_DROP,       /* rejeter la trame, contexte encore recuperable     */
    HDG_SEV_RECOVER     /* resynchroniser les deux cotes, restaurer AVAIL    */
} hdg_severity_t;

/* ------------------------------------------------------------------ */
/* Groupes                                                             */
/* ------------------------------------------------------------------ */

typedef enum
{
    HDG_GROUP_SEC = 0,
    HDG_GROUP_XL,
    HDG_GROUP_TP,
    HDG_GROUP_TIME,
    HDG_GROUP_AVAIL
} hdg_group_t;

/* ------------------------------------------------------------------ */
/* Description                                                         */
/*                                                                     */
/* static inline : le fichier reste purement en-tete, sans .c a lier,  */
/* ce qui permet au fuzzer et au banc de l'inclure sans dependance.    */
/* ------------------------------------------------------------------ */

typedef struct
{
    hdg_invariant_id_t id;
    hdg_group_t        group;
    hdg_severity_t     default_severity;
    const char        *code;     /* etiquette courte, stable, pour les traces */
    const char        *summary;  /* one sentence: what a violation looks like */
} hdg_invariant_info_t;

static inline const hdg_invariant_info_t *hdg_invariant_table(size_t *count)
{
    static const hdg_invariant_info_t TABLE[] = {
        { HDG_INV_SEC_NO_UNAUTH_EFFECT, HDG_GROUP_SEC, HDG_SEV_DROP,
          "SEC-1", "a protected service took effect without a prior unlock" },
        { HDG_INV_SEC_SEED_KEY_BINDING, HDG_GROUP_SEC, HDG_SEV_DROP,
          "SEC-2", "a key was accepted without a bound, unconsumed seed" },
        { HDG_INV_SEC_RELOCK_ON_RESET, HDG_GROUP_SEC, HDG_SEV_RECOVER,
          "SEC-3", "security stayed unlocked across an ECUReset" },
        { HDG_INV_SEC_RELOCK_ON_DEFAULT, HDG_GROUP_SEC, HDG_SEV_RECOVER,
          "SEC-4", "security stayed unlocked after returning to the default session" },
        { HDG_INV_SEC_MONOTONIC_ATTEMPTS, HDG_GROUP_SEC, HDG_SEV_DROP,
          "SEC-5", "the failed-attempt counter was cleared by a transport event" },

        { HDG_INV_XL_TRANSPORT_CANNOT_FORGE_AUTHORITY, HDG_GROUP_XL,
          HDG_SEV_RECOVER,
          "XL-1", "an ISO-TP anomaly forged UDS authority" },
        { HDG_INV_XL_NO_AUTHORITY_CARRYOVER, HDG_GROUP_XL, HDG_SEV_RECOVER,
          "XL-2", "authority survived a transport abort" },
        { HDG_INV_XL_EPOCH_CONSISTENCY, HDG_GROUP_XL, HDG_SEV_RECOVER,
          "XL-3", "gateway and ECU disagreed on epoch or state" },
        { HDG_INV_XL_SINGLE_WRITER, HDG_GROUP_XL, HDG_SEV_DROP,
          "XL-4", "two interleaved transfers were delivered to UDS" },

        { HDG_INV_TP_LENGTH_HONESTY, HDG_GROUP_TP, HDG_SEV_DROP,
          "TP-1", "delivered length differed from the announced length" },
        { HDG_INV_TP_SEQUENCE_MONOTONIC, HDG_GROUP_TP, HDG_SEV_DROP,
          "TP-2", "a sequence number was not the successor modulo 16" },
        { HDG_INV_TP_BOUNDED_BUFFER, HDG_GROUP_TP, HDG_SEV_DROP,
          "TP-3", "the reassembly buffer overflowed" },

        { HDG_INV_TIME_DEADLINE_CONSISTENCY, HDG_GROUP_TIME, HDG_SEV_RECOVER,
          "TIME-1", "N_Cr / N_Bs / S3 diverged between gateway and ECU" },
        { HDG_INV_TIME_NO_STALE_RESUME, HDG_GROUP_TIME, HDG_SEV_DROP,
          "TIME-2", "a late frame resumed an expired transfer" },

        { HDG_INV_AVAIL_RECOVERABLE, HDG_GROUP_AVAIL, HDG_SEV_RECOVER,
          "AVAIL-1", "a valid session became impossible after a blocked attack" },
        { HDG_INV_AVAIL_NO_WEDGED_CONTEXT, HDG_GROUP_AVAIL, HDG_SEV_RECOVER,
          "AVAIL-2", "the ECU was left unable to serve diagnostics" }
    };

    if (count != NULL)
    {
        *count = sizeof(TABLE) / sizeof(TABLE[0]);
    }
    return TABLE;
}

static inline const hdg_invariant_info_t *hdg_invariant_info(
    hdg_invariant_id_t id)
{
    size_t count = 0u;
    const hdg_invariant_info_t *table = hdg_invariant_table(&count);
    size_t i;

    for (i = 0u; i < count; i++)
    {
        if (table[i].id == id)
        {
            return &table[i];
        }
    }
    return NULL;
}

static inline const char *hdg_invariant_code(hdg_invariant_id_t id)
{
    const hdg_invariant_info_t *info = hdg_invariant_info(id);
    return (info != NULL) ? info->code : "INV-?";
}

#endif /* HDG_INVARIANTS_H */
