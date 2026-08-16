/*
 * uds.h
 *
 * Serveur UDS (ISO 14229-1), sous-ensemble.
 *
 * Etat actuel : service 0x10 DiagnosticSessionControl, plus la
 * generation systematique de reponses negatives pour tout le reste.
 *
 * Comme la couche ISO-TP, ce module n'inclut aucun header systeme.
 * Il ne connait ni CAN, ni SocketCAN, ni le transport employe : il
 * recoit une payload de requete et remplit un tampon de reponse.
 * C'est ce qui permettra de le reutiliser au-dessus de DoIP ou d'un
 * backend microcontroleur sans le modifier.
 *
 * Contraintes : aucune allocation dynamique, aucun etat global, tous
 * les tampons appartiennent a l'appelant.
 */

#ifndef UDS_H
#define UDS_H

#include <stdint.h>
#include <stddef.h>   /* NULL */

/* ------------------------------------------------------------------ */
/* Constantes de protocole                                             */
/* ------------------------------------------------------------------ */

/* Identifiants de service (SID). */
#define UDS_SID_DIAGNOSTIC_SESSION_CONTROL   0x10u
#define UDS_SID_ECU_RESET                    0x11u
#define UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION 0x14u
#define UDS_SID_READ_DTC_INFORMATION         0x19u
#define UDS_SID_READ_DATA_BY_IDENTIFIER      0x22u
#define UDS_SID_SECURITY_ACCESS              0x27u
#define UDS_SID_TESTER_PRESENT               0x3Eu

/*
 * Une reponse positive reutilise le SID de la requete augmente de 0x40.
 * 0x10 -> 0x50, 0x22 -> 0x62, 0x27 -> 0x67, etc.
 */
#define UDS_POSITIVE_RESPONSE_OFFSET         0x40u

/*
 * Une reponse negative a toujours la forme :
 *
 *     7F <SID de la requete> <NRC>
 *
 * 0x7F n'est donc pas un service : c'est un marqueur de rejet.
 */
#define UDS_NEGATIVE_RESPONSE_SID            0x7Fu
#define UDS_NEGATIVE_RESPONSE_LEN            3u

/*
 * Bit 7 d'une sous-fonction : suppressPosRspMsgIndicationBit.
 *
 * Quand il vaut 1, le client demande au serveur de NE PAS emettre la
 * reponse positive. Cela sert a limiter la charge du bus, typiquement
 * pour un TesterPresent periodique. Les reponses NEGATIVES restent
 * emises : une erreur doit toujours remonter.
 *
 * La valeur reelle de la sous-fonction s'obtient donc en masquant ce
 * bit, d'ou UDS_SUBFUNCTION_MASK.
 */
#define UDS_SUPPRESS_POS_RSP_BIT             0x80u
#define UDS_SUBFUNCTION_MASK                 0x7Fu

/*
 * Codes de reponse negative (NRC).
 * Sous-ensemble de la table ISO 14229-1 ; seuls certains sont utilises
 * aujourd'hui, les autres serviront aux services a venir.
 */
#define UDS_NRC_GENERAL_REJECT                       0x10u
#define UDS_NRC_SERVICE_NOT_SUPPORTED                0x11u
#define UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED           0x12u
#define UDS_NRC_INCORRECT_MESSAGE_LENGTH             0x13u
#define UDS_NRC_RESPONSE_TOO_LONG                    0x14u
#define UDS_NRC_CONDITIONS_NOT_CORRECT               0x22u
#define UDS_NRC_REQUEST_OUT_OF_RANGE                 0x31u
#define UDS_NRC_SECURITY_ACCESS_DENIED               0x33u
#define UDS_NRC_INVALID_KEY                          0x35u
#define UDS_NRC_EXCEED_NUMBER_OF_ATTEMPTS            0x36u
#define UDS_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED      0x37u
#define UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED_IN_SESSION 0x7Eu
#define UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION     0x7Fu

/*
 * Taille maximale d'une reponse produite par ce module.
 *
 * Depuis que le transport sait segmenter, la limite n'est plus celle
 * d'une trame CAN mais celle que l'on choisit de reserver. 512 octets
 * couvrent largement les services implementes ; redefinissable a la
 * compilation pour une cible a memoire contrainte.
 */
#ifndef UDS_MAX_RESPONSE_SIZE
#define UDS_MAX_RESPONSE_SIZE                512u
#endif

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

/*
 * Les valeurs correspondent volontairement aux sous-fonctions de
 * DiagnosticSessionControl, ce qui evite une table de conversion.
 */
typedef enum
{
    UDS_SESSION_DEFAULT     = 0x01,
    UDS_SESSION_PROGRAMMING = 0x02,
    UDS_SESSION_EXTENDED    = 0x03
} uds_session_t;

/*
 * S3server : delai au-dela duquel une session non par defaut retombe
 * d'elle-meme en session par defaut faute d'activite.
 *
 * C'est une propriete de securite, pas un detail de confort : une
 * session etendue laissee ouverte indefiniment est une porte ouverte
 * indefiniment. TesterPresent (0x3E) existe precisement pour repousser
 * cette echeance tant que l'outil de diagnostic est la.
 *
 * La valeur usuelle de la norme est de 5 secondes.
 */
#ifndef UDS_S3_SERVER_TIMEOUT_MS
#define UDS_S3_SERVER_TIMEOUT_MS  5000u
#endif

/* ------------------------------------------------------------------ */
/* Niveaux de securite                                                 */
/* ------------------------------------------------------------------ */

#define UDS_SECURITY_LOCKED       0u
#define UDS_SECURITY_LEVEL_1      1u

/* Sous-fonctions de SecurityAccess pour le niveau 1. */
#define UDS_SECURITY_REQUEST_SEED 0x01u
#define UDS_SECURITY_SEND_KEY     0x02u

/* Longueur de la graine et de la cle, en octets. */
#define UDS_SECURITY_SEED_LEN     4u
#define UDS_SECURITY_KEY_LEN      4u

/*
 * Protection anti-force-brute : au-dela de ce nombre de cles fausses
 * consecutives, le serveur se verrouille pour une duree fixe.
 */
#define UDS_SECURITY_MAX_ATTEMPTS 3u

#ifndef UDS_SECURITY_LOCKOUT_MS
#define UDS_SECURITY_LOCKOUT_MS   10000u
#endif

/* ------------------------------------------------------------------ */
/* Resultats                                                           */
/* ------------------------------------------------------------------ */

typedef enum
{
    UDS_OK = 0,                 /* une reponse est prete dans le tampon */
    UDS_NO_RESPONSE,            /* ne rien emettre sur le bus           */
    UDS_ERR_NULL_POINTER,
    UDS_ERR_BUFFER_TOO_SMALL,
    UDS_ERR_DID_NOT_FOUND,      /* renvoye par un fournisseur de DID    */
    UDS_ERR_NOT_SUPPORTED       /* renvoye par un fournisseur applicatif */
} uds_result_t;

/* ------------------------------------------------------------------ */
/* Fourniture des donnees applicatives                                 */
/* ------------------------------------------------------------------ */

/*
 * Le serveur UDS ne connait aucune donnee de vehicule. Il sait
 * seulement mettre en forme une requete 0x22 et sa reponse ; la valeur
 * elle-meme est fournie par l'application via ce pointeur de fonction.
 *
 * Cette indirection est ce qui evite que uds.c contienne un jour un
 * regime moteur ou un VIN. Le meme serveur peut servir un ECU moteur ou
 * un calculateur de freinage sans etre modifie, et les tests peuvent
 * injecter un fournisseur factice.
 *
 * did          : identifiant demande
 * out          : ou ecrire la valeur
 * out_capacity : place disponible
 * out_len      : recoit la taille ecrite
 * user_ctx     : donnees applicatives opaques passees a uds_set_did_provider
 *
 * Retour attendu :
 *   UDS_OK                      valeur ecrite
 *   UDS_ERR_DID_NOT_FOUND       identifiant inconnu -> NRC 0x31
 *   UDS_ERR_BUFFER_TOO_SMALL    valeur trop grande pour le transport
 *                               -> NRC 0x14 responseTooLong
 */
typedef uds_result_t (*uds_did_read_fn)(uint16_t did,
                                        uint8_t *out,
                                        uint16_t out_capacity,
                                        uint16_t *out_len,
                                        void *user_ctx);

/*
 * Lecture des codes defaut.
 *
 * Ecrit une suite d'enregistrements de 4 octets : 3 octets de code
 * defaut suivis de l'octet de statut. Seuls les defauts dont le statut
 * recoupe status_mask doivent etre rapportes.
 */
typedef uds_result_t (*uds_dtc_read_fn)(uint8_t status_mask,
                                        uint8_t *out,
                                        uint16_t out_capacity,
                                        uint16_t *out_len,
                                        void *user_ctx);

/* Effacement des codes defaut d'un groupe. 0xFFFFFF = tous. */
typedef uds_result_t (*uds_dtc_clear_fn)(uint32_t group_of_dtc,
                                         void *user_ctx);

/* Reinitialisation du calculateur. */
typedef uds_result_t (*uds_ecu_reset_fn)(uint8_t reset_type,
                                         void *user_ctx);

typedef struct
{
    uds_session_t session;

    /* UDS_SECURITY_LOCKED tant qu'aucune cle valide n'a ete presentee. */
    uint8_t  security_level;

    /* Date de la derniere requete traitee, pour S3server. */
    uint32_t last_activity_ms;

    /* --- SecurityAccess --- */
    uint32_t current_seed;
    uint8_t  seed_pending;      /* une graine attend sa cle */
    uint8_t  failed_attempts;
    uint32_t lockout_until_ms;
    uint8_t  locked_out;
    uint32_t seed_state;        /* etat du generateur de graines */

    /* --- Interface applicative --- */
    uds_did_read_fn   did_read;
    uds_dtc_read_fn   dtc_read;
    uds_dtc_clear_fn  dtc_clear;
    uds_ecu_reset_fn  ecu_reset;
    void             *user_ctx;
} uds_context_t;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Place le contexte dans son etat initial : session par defaut, aucun
 * fournisseur de DID. Sans fournisseur, le service 0x22 est refuse par
 * un NRC serviceNotSupported : un serveur qui ne peut rien lire ne
 * "supporte" pas reellement le service.
 */
void uds_init(uds_context_t *ctx);

/* Branche la source des donnees applicatives lues par 0x22. */
void uds_set_did_provider(uds_context_t *ctx,
                          uds_did_read_fn did_read,
                          void *user_ctx);

/* Branche la lecture et l'effacement des codes defaut (0x19, 0x14). */
void uds_set_dtc_provider(uds_context_t *ctx,
                          uds_dtc_read_fn dtc_read,
                          uds_dtc_clear_fn dtc_clear);

/* Branche la reinitialisation du calculateur (0x11). */
void uds_set_reset_handler(uds_context_t *ctx,
                           uds_ecu_reset_fn ecu_reset);

/*
 * Injecte de l'entropie dans le generateur de graines de SecurityAccess.
 *
 * L'algorithme de generation est deterministe ; sans cet appel, deux
 * executions produiraient la meme suite de graines. L'application doit
 * fournir une valeur variable au demarrage.
 *
 * ATTENTION : ce generateur est un LCG, adapte a une demonstration mais
 * PAS cryptographiquement sur. Un calculateur reel doit utiliser un
 * generateur materiel.
 */
void uds_seed_entropy(uds_context_t *ctx, uint32_t entropy);

/*
 * Derivation de cle de SecurityAccess.
 *
 * DEMONSTRATION UNIQUEMENT - CE N'EST PAS UN MECANISME SUR.
 *
 * L'algorithme est public, donc quiconque lit ce depot peut calculer la
 * cle. Il sert a montrer la MECANIQUE du protocole seed/key, pas a
 * proteger quoi que ce soit. Une implementation reelle derive la cle
 * d'un secret partage jamais transmis, typiquement via HMAC-SHA256, et
 * ne place jamais l'algorithme dans un depot public.
 */
uint32_t uds_demo_key_from_seed(uint32_t seed);

/*
 * A appeler periodiquement, meme sans trafic.
 *
 * Fait retomber la session en session par defaut apres S3server, et
 * leve le verrouillage anti-force-brute quand son delai est ecoule.
 */
void uds_poll(uds_context_t *ctx, uint32_t now_ms);

/*
 * Traite une requete UDS.
 *
 * ctx                : contexte serveur, mis a jour si la requete
 *                      change la session
 * request            : payload UDS (SID en premier octet), sans PCI
 * request_len        : longueur de cette payload
 * response           : tampon de sortie fourni par l'appelant
 * response_capacity  : taille de ce tampon
 * response_len       : recoit la longueur de la reponse produite
 *
 * Retour :
 *   UDS_OK                    reponse prete, a emettre
 *   UDS_NO_RESPONSE           rien a emettre (requete vide, ou
 *                             suppressPosRspMsgIndicationBit actif)
 *   UDS_ERR_NULL_POINTER
 *   UDS_ERR_BUFFER_TOO_SMALL
 *
 * Une requete inconnue ou malformee ne provoque jamais d'erreur de
 * retour : elle produit une reponse NEGATIVE, ce qui est le
 * comportement attendu d'un serveur de diagnostic.
 */
uds_result_t uds_handle_request(uds_context_t *ctx,
                                const uint8_t *request,
                                uint16_t request_len,
                                uint32_t now_ms,
                                uint8_t *response,
                                uint16_t response_capacity,
                                uint16_t *response_len);

/* Libelles pour les traces. Aucune allocation. */
const char *uds_session_to_string(uds_session_t session);
const char *uds_nrc_to_string(uint8_t nrc);
const char *uds_result_to_string(uds_result_t result);
const char *uds_sid_to_string(uint8_t sid);

#endif /* UDS_H */
