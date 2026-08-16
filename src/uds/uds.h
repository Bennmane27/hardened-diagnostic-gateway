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
#define UDS_SID_READ_DATA_BY_IDENTIFIER      0x22u

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

/* ------------------------------------------------------------------ */
/* Resultats                                                           */
/* ------------------------------------------------------------------ */

typedef enum
{
    UDS_OK = 0,                 /* une reponse est prete dans le tampon */
    UDS_NO_RESPONSE,            /* ne rien emettre sur le bus           */
    UDS_ERR_NULL_POINTER,
    UDS_ERR_BUFFER_TOO_SMALL,
    UDS_ERR_DID_NOT_FOUND       /* renvoye par un fournisseur de DID    */
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

typedef struct
{
    uds_session_t   session;
    uds_did_read_fn did_read;
    void           *user_ctx;
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
                                uint8_t *response,
                                uint16_t response_capacity,
                                uint16_t *response_len);

/* Libelles pour les traces. Aucune allocation. */
const char *uds_session_to_string(uds_session_t session);
const char *uds_nrc_to_string(uint8_t nrc);
const char *uds_result_to_string(uds_result_t result);

#endif /* UDS_H */
