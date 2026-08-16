/*
 * uds.c
 *
 * Serveur UDS, sous-ensemble d'ISO 14229-1.
 *
 * Aucun header systeme : ce module ne connait pas son transport.
 */

#include "uds.h"

/*
 * Parametres de temporisation renvoyes dans la reponse positive a
 * DiagnosticSessionControl (sessionParameterRecord).
 *
 * P2Server_max  : delai maximal, en millisecondes, entre la requete et
 *                 la reponse du serveur.
 * P2*Server_max : delai maximal apres une reponse negative 0x78
 *                 (requestCorrectlyReceived-ResponsePending). Sa
 *                 resolution est de 10 ms, d'ou la division.
 *
 * Les deux champs sont encodes sur 2 octets en big endian, l'octet de
 * poids fort en premier. C'est la convention d'ISO 14229 ; ne pas la
 * confondre avec l'ordre natif du processeur, d'ou l'encodage explicite
 * octet par octet plus bas plutot qu'une copie de uint16_t.
 */
#define UDS_P2_SERVER_MAX_MS        50u
#define UDS_P2_STAR_SERVER_MAX_MS   5000u
#define UDS_P2_STAR_RESOLUTION_MS   10u

/* SID + sous-fonction : longueur exacte d'une requete 0x10. */
#define UDS_DSC_REQUEST_LEN         2u

/* 0x50 + sous-fonction + 4 octets de sessionParameterRecord. */
#define UDS_DSC_RESPONSE_LEN        6u

/*
 * 0x22 : SID + identifiant sur 2 octets.
 *
 * La norme autorise plusieurs identifiants dans une meme requete. Ce
 * serveur n'en accepte qu'un : c'est une limite assumee, documentee
 * dans le README, et non un oubli.
 */
#define UDS_RDBI_REQUEST_LEN        3u

/* 0x62 + les 2 octets de l'identifiant, avant la valeur. */
#define UDS_RDBI_HEADER_LEN         3u

/* 0x11 : SID + type de reinitialisation. */
#define UDS_RESET_REQUEST_LEN       2u
#define UDS_RESET_HARD              0x01u
#define UDS_RESET_SOFT              0x03u

/* 0x3E : SID + sous-fonction (toujours 0x00). */
#define UDS_TESTER_PRESENT_LEN      2u
#define UDS_TESTER_PRESENT_SUBFN    0x00u

/* 0x19 : la seule sous-fonction implementee. */
#define UDS_DTC_REPORT_BY_STATUS_MASK 0x02u
#define UDS_RDTC_REQUEST_LEN          3u

/*
 * Masque de disponibilite renvoye dans la reponse a 0x19 02 : il dit au
 * client quels bits de statut ce calculateur sait renseigner.
 * Bit 0 testFailed, bit 3 confirmedDTC.
 */
#define UDS_DTC_AVAILABILITY_MASK     0x09u

/* 0x14 : SID + groupe de defauts sur 3 octets. */
#define UDS_CLEAR_REQUEST_LEN         4u

/* ------------------------------------------------------------------ */
/* Libelles                                                            */
/* ------------------------------------------------------------------ */

const char *uds_session_to_string(uds_session_t session)
{
    switch (session)
    {
    case UDS_SESSION_DEFAULT:
        return "Default Session";
    case UDS_SESSION_PROGRAMMING:
        return "Programming Session";
    case UDS_SESSION_EXTENDED:
        return "Extended Diagnostic Session";
    default:
        return "session inconnue";
    }
}

const char *uds_nrc_to_string(uint8_t nrc)
{
    switch (nrc)
    {
    case UDS_NRC_GENERAL_REJECT:
        return "generalReject";
    case UDS_NRC_SERVICE_NOT_SUPPORTED:
        return "serviceNotSupported";
    case UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED:
        return "subFunctionNotSupported";
    case UDS_NRC_INCORRECT_MESSAGE_LENGTH:
        return "incorrectMessageLengthOrInvalidFormat";
    case UDS_NRC_RESPONSE_TOO_LONG:
        return "responseTooLong";
    case UDS_NRC_CONDITIONS_NOT_CORRECT:
        return "conditionsNotCorrect";
    case UDS_NRC_REQUEST_OUT_OF_RANGE:
        return "requestOutOfRange";
    case UDS_NRC_SECURITY_ACCESS_DENIED:
        return "securityAccessDenied";
    case UDS_NRC_INVALID_KEY:
        return "invalidKey";
    case UDS_NRC_EXCEED_NUMBER_OF_ATTEMPTS:
        return "exceedNumberOfAttempts";
    case UDS_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED:
        return "requiredTimeDelayNotExpired";
    case UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED_IN_SESSION:
        return "subFunctionNotSupportedInActiveSession";
    case UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION:
        return "serviceNotSupportedInActiveSession";
    default:
        return "NRC inconnu";
    }
}

const char *uds_sid_to_string(uint8_t sid)
{
    switch (sid)
    {
    case UDS_SID_DIAGNOSTIC_SESSION_CONTROL:
        return "DiagnosticSessionControl";
    case UDS_SID_ECU_RESET:
        return "ECUReset";
    case UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION:
        return "ClearDiagnosticInformation";
    case UDS_SID_READ_DTC_INFORMATION:
        return "ReadDTCInformation";
    case UDS_SID_READ_DATA_BY_IDENTIFIER:
        return "ReadDataByIdentifier";
    case UDS_SID_SECURITY_ACCESS:
        return "SecurityAccess";
    case UDS_SID_TESTER_PRESENT:
        return "TesterPresent";
    default:
        return "service inconnu";
    }
}

const char *uds_result_to_string(uds_result_t result)
{
    switch (result)
    {
    case UDS_OK:
        return "OK";
    case UDS_NO_RESPONSE:
        return "aucune reponse a emettre";
    case UDS_ERR_NULL_POINTER:
        return "pointeur NULL";
    case UDS_ERR_BUFFER_TOO_SMALL:
        return "tampon de reponse trop petit";
    case UDS_ERR_DID_NOT_FOUND:
        return "identifiant de donnee inconnu";
    case UDS_ERR_NOT_SUPPORTED:
        return "non supporte par l'application";
    default:
        return "erreur inconnue";
    }
}

/* ------------------------------------------------------------------ */
/* Fabrication d'une reponse negative                                  */
/* ------------------------------------------------------------------ */

/*
 * Ecrit 7F <SID> <NRC>.
 *
 * Le SID echo permet au client de savoir quelle requete a ete rejetee
 * lorsque plusieurs sont en vol.
 */
static uds_result_t make_negative_response(uint8_t sid,
                                           uint8_t nrc,
                                           uint8_t *response,
                                           uint16_t response_capacity,
                                           uint16_t *response_len)
{
    if (response_capacity < UDS_NEGATIVE_RESPONSE_LEN)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    response[0] = UDS_NEGATIVE_RESPONSE_SID;
    response[1] = sid;
    response[2] = nrc;

    *response_len = UDS_NEGATIVE_RESPONSE_LEN;

    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* 0x10 DiagnosticSessionControl                                       */
/* ------------------------------------------------------------------ */

static uds_result_t handle_diagnostic_session_control(
    uds_context_t *ctx,
    const uint8_t *request,
    uint16_t request_len,
    uint8_t *response,
    uint16_t response_capacity,
    uint16_t *response_len)
{
    uint8_t raw_subfunction;
    uint8_t subfunction;
    uint8_t suppress_positive_response;
    uint16_t p2_star;

    /*
     * La requete doit faire exactement 2 octets : le SID et la
     * sous-fonction. Ni plus court, ni plus long. Accepter une longueur
     * approximative est une des portes d'entree classiques d'un parser
     * de diagnostic.
     */
    if (request_len != UDS_DSC_REQUEST_LEN)
    {
        return make_negative_response(UDS_SID_DIAGNOSTIC_SESSION_CONTROL,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    raw_subfunction = request[1];

    /* Bit 7 : demande de suppression de la reponse positive. */
    suppress_positive_response =
        (uint8_t)((raw_subfunction & UDS_SUPPRESS_POS_RSP_BIT) != 0u);

    /* Bits 6..0 : valeur reelle de la sous-fonction. */
    subfunction = (uint8_t)(raw_subfunction & UDS_SUBFUNCTION_MASK);

    switch (subfunction)
    {
    case (uint8_t)UDS_SESSION_DEFAULT:
    case (uint8_t)UDS_SESSION_EXTENDED:
        ctx->session = (uds_session_t)subfunction;
        break;

    /*
     * La session de programmation est une sous-fonction valide de la
     * norme, mais ce serveur ne l'implemente pas encore. On refuse
     * donc explicitement plutot que de l'accepter sans effet.
     */
    default:
        return make_negative_response(UDS_SID_DIAGNOSTIC_SESSION_CONTROL,
                                      UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    /*
     * La session a change. Si le client a demande le silence, on ne
     * repond rien : le changement d'etat a bien eu lieu.
     */
    if (suppress_positive_response != 0u)
    {
        *response_len = 0u;
        return UDS_NO_RESPONSE;
    }

    if (response_capacity < UDS_DSC_RESPONSE_LEN)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    response[0] = (uint8_t)(UDS_SID_DIAGNOSTIC_SESSION_CONTROL +
                            UDS_POSITIVE_RESPONSE_OFFSET);
    response[1] = subfunction;

    /* sessionParameterRecord, big endian. */
    response[2] = (uint8_t)((UDS_P2_SERVER_MAX_MS >> 8) & 0xFFu);
    response[3] = (uint8_t)(UDS_P2_SERVER_MAX_MS & 0xFFu);

    p2_star = (uint16_t)(UDS_P2_STAR_SERVER_MAX_MS /
                         UDS_P2_STAR_RESOLUTION_MS);

    response[4] = (uint8_t)((p2_star >> 8) & 0xFFu);
    response[5] = (uint8_t)(p2_star & 0xFFu);

    *response_len = UDS_DSC_RESPONSE_LEN;

    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* 0x22 ReadDataByIdentifier                                           */
/* ------------------------------------------------------------------ */

static uds_result_t handle_read_data_by_identifier(
    uds_context_t *ctx,
    const uint8_t *request,
    uint16_t request_len,
    uint8_t *response,
    uint16_t response_capacity,
    uint16_t *response_len)
{
    uint16_t did;
    uint16_t data_len = 0u;
    uds_result_t provider_res;

    /*
     * Il faut au minimum de quoi ecrire une reponse negative, sinon on
     * ne peut meme pas signaler l'erreur.
     */
    if (response_capacity < UDS_NEGATIVE_RESPONSE_LEN)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    if (request_len != UDS_RDBI_REQUEST_LEN)
    {
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    if (ctx->did_read == NULL)
    {
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    /* L'identifiant est code sur 2 octets, poids fort en premier. */
    did = (uint16_t)(((uint16_t)request[1] << 8) | (uint16_t)request[2]);

    /*
     * On ne peut pas appeler le fournisseur si la place restante ne
     * suffit meme pas a l'en-tete de reponse.
     */
    if (response_capacity < UDS_RDBI_HEADER_LEN)
    {
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_RESPONSE_TOO_LONG,
                                      response, response_capacity,
                                      response_len);
    }

    /*
     * La valeur est ecrite directement a sa place finale, juste apres
     * l'en-tete : aucune copie intermediaire, aucun tampon temporaire.
     * En cas d'echec, l'en-tete n'est jamais ecrit et le tampon est
     * ecrase par la reponse negative.
     */
    provider_res = ctx->did_read(did,
                                 &response[UDS_RDBI_HEADER_LEN],
                                 (uint16_t)(response_capacity -
                                           UDS_RDBI_HEADER_LEN),
                                 &data_len,
                                 ctx->user_ctx);

    switch (provider_res)
    {
    case UDS_OK:
        response[0] = (uint8_t)(UDS_SID_READ_DATA_BY_IDENTIFIER +
                                UDS_POSITIVE_RESPONSE_OFFSET);
        response[1] = (uint8_t)((did >> 8) & 0xFFu);
        response[2] = (uint8_t)(did & 0xFFu);

        *response_len = (uint16_t)(UDS_RDBI_HEADER_LEN + data_len);
        return UDS_OK;

    case UDS_ERR_DID_NOT_FOUND:
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_REQUEST_OUT_OF_RANGE,
                                      response, response_capacity,
                                      response_len);

    /*
     * La valeur existe mais ne tient pas dans ce que le transport sait
     * emettre. C'est exactement le cas prevu par responseTooLong : la
     * limite du reseau remonte comme une erreur de protocole, pas comme
     * une troncature silencieuse.
     */
    case UDS_ERR_BUFFER_TOO_SMALL:
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_RESPONSE_TOO_LONG,
                                      response, response_capacity,
                                      response_len);

    default:
        return make_negative_response(UDS_SID_READ_DATA_BY_IDENTIFIER,
                                      UDS_NRC_GENERAL_REJECT,
                                      response, response_capacity,
                                      response_len);
    }
}


/* ------------------------------------------------------------------ */
/* Regles d'acces                                                      */
/*                                                                     */
/* Une table plutot qu'une cascade de conditions dispersees dans les    */
/* handlers : la politique d'acces se lit d'un coup d'oeil, et un       */
/* service ajoute sans regle se voit immediatement.                     */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint8_t sid;
    uint8_t requires_extended_session;  /* refuse en session par defaut */
    uint8_t requires_security_unlock;   /* refuse tant que verrouille   */
} service_rule_t;

static const service_rule_t SERVICE_RULES[] = {
    /* SID                                     session  securite */
    { UDS_SID_DIAGNOSTIC_SESSION_CONTROL,          0u,      0u },
    { UDS_SID_TESTER_PRESENT,                      0u,      0u },
    { UDS_SID_READ_DATA_BY_IDENTIFIER,             0u,      0u },
    { UDS_SID_READ_DTC_INFORMATION,                0u,      0u },
    { UDS_SID_SECURITY_ACCESS,                     1u,      0u },
    { UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,        1u,      0u },
    /*
     * ECUReset est la commande sensible de demonstration : elle exige
     * la session etendue ET un deverrouillage par SecurityAccess.
     */
    { UDS_SID_ECU_RESET,                           1u,      1u }
};

#define SERVICE_RULES_COUNT \
    (sizeof(SERVICE_RULES) / sizeof(SERVICE_RULES[0]))

static const service_rule_t *find_rule(uint8_t sid)
{
    size_t i;

    for (i = 0u; i < SERVICE_RULES_COUNT; i++)
    {
        if (SERVICE_RULES[i].sid == sid)
        {
            return &SERVICE_RULES[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 0x3E TesterPresent                                                  */
/* ------------------------------------------------------------------ */

/*
 * Ne fait rien, et c'est tout son role : le seul fait d'avoir ete
 * traite a deja repousse l'echeance S3server dans uds_handle_request.
 * Un outil de diagnostic l'emet periodiquement, en general avec le bit
 * de suppression arme pour ne pas encombrer le bus.
 */
static uds_result_t handle_tester_present(uds_context_t *ctx,
                                          const uint8_t *request,
                                          uint16_t request_len,
                                          uint8_t *response,
                                          uint16_t response_capacity,
                                          uint16_t *response_len)
{
    uint8_t raw_subfunction;
    uint8_t suppress;

    (void)ctx;

    if (request_len != UDS_TESTER_PRESENT_LEN)
    {
        return make_negative_response(UDS_SID_TESTER_PRESENT,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    raw_subfunction = request[1];
    suppress = (uint8_t)((raw_subfunction & UDS_SUPPRESS_POS_RSP_BIT) != 0u);

    if ((raw_subfunction & UDS_SUBFUNCTION_MASK) != UDS_TESTER_PRESENT_SUBFN)
    {
        return make_negative_response(UDS_SID_TESTER_PRESENT,
                                      UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    if (suppress != 0u)
    {
        *response_len = 0u;
        return UDS_NO_RESPONSE;
    }

    if (response_capacity < 2u)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    response[0] = (uint8_t)(UDS_SID_TESTER_PRESENT +
                            UDS_POSITIVE_RESPONSE_OFFSET);
    response[1] = UDS_TESTER_PRESENT_SUBFN;
    *response_len = 2u;

    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* 0x11 ECUReset                                                       */
/* ------------------------------------------------------------------ */

static uds_result_t handle_ecu_reset(uds_context_t *ctx,
                                     const uint8_t *request,
                                     uint16_t request_len,
                                     uint8_t *response,
                                     uint16_t response_capacity,
                                     uint16_t *response_len)
{
    uint8_t reset_type;

    if (request_len != UDS_RESET_REQUEST_LEN)
    {
        return make_negative_response(UDS_SID_ECU_RESET,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    reset_type = (uint8_t)(request[1] & UDS_SUBFUNCTION_MASK);

    if ((reset_type != UDS_RESET_HARD) && (reset_type != UDS_RESET_SOFT))
    {
        return make_negative_response(UDS_SID_ECU_RESET,
                                      UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    if (ctx->ecu_reset == NULL)
    {
        return make_negative_response(UDS_SID_ECU_RESET,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    if (ctx->ecu_reset(reset_type, ctx->user_ctx) != UDS_OK)
    {
        return make_negative_response(UDS_SID_ECU_RESET,
                                      UDS_NRC_CONDITIONS_NOT_CORRECT,
                                      response, response_capacity,
                                      response_len);
    }

    /*
     * Une reinitialisation ramene le calculateur a son etat de
     * demarrage : session par defaut et securite reverrouillee. Laisser
     * un acces ouvert en travers d'un reset serait une faille.
     */
    ctx->session        = UDS_SESSION_DEFAULT;
    ctx->security_level = UDS_SECURITY_LOCKED;
    ctx->seed_pending   = 0u;

    if (response_capacity < 2u)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    response[0] = (uint8_t)(UDS_SID_ECU_RESET + UDS_POSITIVE_RESPONSE_OFFSET);
    response[1] = reset_type;
    *response_len = 2u;

    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* 0x27 SecurityAccess                                                 */
/* ------------------------------------------------------------------ */

/*
 * Generateur de graines.
 *
 * Congruentiel lineaire : rapide, deterministe, et NON
 * cryptographique. Il convient a une demonstration du protocole ; un
 * calculateur reel doit tirer sa graine d'un generateur materiel, sans
 * quoi un attaquant peut predire la suite apres quelques observations.
 * Ce choix est documente plutot que dissimule.
 */
static uint32_t next_seed(uds_context_t *ctx)
{
    ctx->seed_state = (ctx->seed_state * 1103515245u) + 12345u;
    return ctx->seed_state ^ 0x5A5A5A5Au;
}

uint32_t uds_demo_key_from_seed(uint32_t seed)
{
    uint32_t k = seed ^ 0xA5A5A5A5u;

    /* Rotation de 3 bits vers la gauche sur 32 bits. */
    k = (uint32_t)((k << 3) | (k >> 29));
    k = (uint32_t)(k + 0x3C3C3C3Cu);

    return k;
}

static uds_result_t handle_security_access(uds_context_t *ctx,
                                           const uint8_t *request,
                                           uint16_t request_len,
                                           uint32_t now_ms,
                                           uint8_t *response,
                                           uint16_t response_capacity,
                                           uint16_t *response_len)
{
    uint8_t subfunction;

    if (request_len < 2u)
    {
        return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    subfunction = (uint8_t)(request[1] & UDS_SUBFUNCTION_MASK);

    /*
     * Verrouillage anti-force-brute encore actif : on refuse tout,
     * y compris une demande de graine, sinon l'attaquant relancerait
     * simplement un cycle.
     */
    if (ctx->locked_out != 0u)
    {
        return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                      UDS_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED,
                                      response, response_capacity,
                                      response_len);
    }

    if (subfunction == UDS_SECURITY_REQUEST_SEED)
    {
        uint32_t seed;

        if (request_len != 2u)
        {
            return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                          UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                          response, response_capacity,
                                          response_len);
        }

        if (response_capacity < (2u + UDS_SECURITY_SEED_LEN))
        {
            return UDS_ERR_BUFFER_TOO_SMALL;
        }

        /*
         * Deja deverrouille : la norme prevoit de renvoyer une graine
         * nulle pour signaler "rien a faire" plutot que de relancer un
         * echange inutile.
         */
        if (ctx->security_level != UDS_SECURITY_LOCKED)
        {
            seed = 0u;
            ctx->seed_pending = 0u;
        }
        else
        {
            seed = next_seed(ctx);
            ctx->current_seed = seed;
            ctx->seed_pending = 1u;
        }

        response[0] = (uint8_t)(UDS_SID_SECURITY_ACCESS +
                                UDS_POSITIVE_RESPONSE_OFFSET);
        response[1] = UDS_SECURITY_REQUEST_SEED;
        response[2] = (uint8_t)((seed >> 24) & 0xFFu);
        response[3] = (uint8_t)((seed >> 16) & 0xFFu);
        response[4] = (uint8_t)((seed >> 8) & 0xFFu);
        response[5] = (uint8_t)(seed & 0xFFu);

        *response_len = (uint16_t)(2u + UDS_SECURITY_SEED_LEN);
        return UDS_OK;
    }

    if (subfunction == UDS_SECURITY_SEND_KEY)
    {
        uint32_t received_key;
        uint32_t expected_key;

        if (request_len != (2u + UDS_SECURITY_KEY_LEN))
        {
            return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                          UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                          response, response_capacity,
                                          response_len);
        }

        /*
         * Une cle sans graine en attente est soit une erreur de
         * sequence, soit un rejeu. Dans les deux cas on refuse : c'est
         * ce qui empeche de rejouer une cle capturee auparavant.
         */
        if (ctx->seed_pending == 0u)
        {
            return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                          UDS_NRC_CONDITIONS_NOT_CORRECT,
                                          response, response_capacity,
                                          response_len);
        }

        received_key = (((uint32_t)request[2]) << 24) |
                       (((uint32_t)request[3]) << 16) |
                       (((uint32_t)request[4]) << 8)  |
                       ((uint32_t)request[5]);

        expected_key = uds_demo_key_from_seed(ctx->current_seed);

        if (received_key != expected_key)
        {
            ctx->failed_attempts++;

            /*
             * La graine est consommee des le premier essai rate :
             * l'attaquant doit en redemander une, ce qui l'empeche de
             * balayer l'espace des cles contre une graine figee.
             */
            ctx->seed_pending = 0u;

            if (ctx->failed_attempts >= UDS_SECURITY_MAX_ATTEMPTS)
            {
                ctx->locked_out      = 1u;
                ctx->lockout_until_ms = now_ms + UDS_SECURITY_LOCKOUT_MS;

                return make_negative_response(
                    UDS_SID_SECURITY_ACCESS,
                    UDS_NRC_EXCEED_NUMBER_OF_ATTEMPTS,
                    response, response_capacity, response_len);
            }

            return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                          UDS_NRC_INVALID_KEY,
                                          response, response_capacity,
                                          response_len);
        }

        /* Cle correcte. */
        ctx->security_level  = UDS_SECURITY_LEVEL_1;
        ctx->failed_attempts = 0u;
        ctx->seed_pending    = 0u;

        if (response_capacity < 2u)
        {
            return UDS_ERR_BUFFER_TOO_SMALL;
        }

        response[0] = (uint8_t)(UDS_SID_SECURITY_ACCESS +
                                UDS_POSITIVE_RESPONSE_OFFSET);
        response[1] = UDS_SECURITY_SEND_KEY;
        *response_len = 2u;

        return UDS_OK;
    }

    return make_negative_response(UDS_SID_SECURITY_ACCESS,
                                  UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
                                  response, response_capacity,
                                  response_len);
}

/* ------------------------------------------------------------------ */
/* 0x19 ReadDTCInformation                                             */
/* ------------------------------------------------------------------ */

static uds_result_t handle_read_dtc_information(uds_context_t *ctx,
                                                const uint8_t *request,
                                                uint16_t request_len,
                                                uint8_t *response,
                                                uint16_t response_capacity,
                                                uint16_t *response_len)
{
    uint8_t subfunction;
    uint8_t status_mask;
    uint16_t dtc_len = 0u;
    uds_result_t res;

    if (request_len < 2u)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    subfunction = (uint8_t)(request[1] & UDS_SUBFUNCTION_MASK);

    if (subfunction != UDS_DTC_REPORT_BY_STATUS_MASK)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    if (request_len != UDS_RDTC_REQUEST_LEN)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    if (ctx->dtc_read == NULL)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    status_mask = request[2];

    /* 0x59 + sous-fonction + masque de disponibilite, puis les defauts. */
    if (response_capacity < 3u)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    res = ctx->dtc_read(status_mask,
                        &response[3],
                        (uint16_t)(response_capacity - 3u),
                        &dtc_len,
                        ctx->user_ctx);

    if (res == UDS_ERR_BUFFER_TOO_SMALL)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_RESPONSE_TOO_LONG,
                                      response, response_capacity,
                                      response_len);
    }

    if (res != UDS_OK)
    {
        return make_negative_response(UDS_SID_READ_DTC_INFORMATION,
                                      UDS_NRC_CONDITIONS_NOT_CORRECT,
                                      response, response_capacity,
                                      response_len);
    }

    response[0] = (uint8_t)(UDS_SID_READ_DTC_INFORMATION +
                            UDS_POSITIVE_RESPONSE_OFFSET);
    response[1] = UDS_DTC_REPORT_BY_STATUS_MASK;
    response[2] = UDS_DTC_AVAILABILITY_MASK;

    *response_len = (uint16_t)(3u + dtc_len);
    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* 0x14 ClearDiagnosticInformation                                     */
/* ------------------------------------------------------------------ */

static uds_result_t handle_clear_diagnostic_information(
    uds_context_t *ctx,
    const uint8_t *request,
    uint16_t request_len,
    uint8_t *response,
    uint16_t response_capacity,
    uint16_t *response_len)
{
    uint32_t group;

    if (request_len != UDS_CLEAR_REQUEST_LEN)
    {
        return make_negative_response(UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
                                      UDS_NRC_INCORRECT_MESSAGE_LENGTH,
                                      response, response_capacity,
                                      response_len);
    }

    if (ctx->dtc_clear == NULL)
    {
        return make_negative_response(UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    /* Le groupe est code sur 3 octets, poids fort en premier. */
    group = (((uint32_t)request[1]) << 16) |
            (((uint32_t)request[2]) << 8)  |
            ((uint32_t)request[3]);

    if (ctx->dtc_clear(group, ctx->user_ctx) != UDS_OK)
    {
        return make_negative_response(UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
                                      UDS_NRC_REQUEST_OUT_OF_RANGE,
                                      response, response_capacity,
                                      response_len);
    }

    if (response_capacity < 1u)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    response[0] = (uint8_t)(UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION +
                            UDS_POSITIVE_RESPONSE_OFFSET);
    *response_len = 1u;

    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* Point d'entree                                                      */
/* ------------------------------------------------------------------ */

void uds_init(uds_context_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    ctx->session          = UDS_SESSION_DEFAULT;
    ctx->security_level   = UDS_SECURITY_LOCKED;
    ctx->last_activity_ms = 0u;

    ctx->current_seed     = 0u;
    ctx->seed_pending     = 0u;
    ctx->failed_attempts  = 0u;
    ctx->lockout_until_ms = 0u;
    ctx->locked_out       = 0u;
    ctx->seed_state       = 0x12345678u;

    ctx->did_read  = NULL;
    ctx->dtc_read  = NULL;
    ctx->dtc_clear = NULL;
    ctx->ecu_reset = NULL;
    ctx->user_ctx  = NULL;
}

void uds_set_did_provider(uds_context_t *ctx,
                          uds_did_read_fn did_read,
                          void *user_ctx)
{
    if (ctx != NULL)
    {
        ctx->did_read = did_read;
        ctx->user_ctx = user_ctx;
    }
}

void uds_set_dtc_provider(uds_context_t *ctx,
                          uds_dtc_read_fn dtc_read,
                          uds_dtc_clear_fn dtc_clear)
{
    if (ctx != NULL)
    {
        ctx->dtc_read  = dtc_read;
        ctx->dtc_clear = dtc_clear;
    }
}

void uds_set_reset_handler(uds_context_t *ctx, uds_ecu_reset_fn ecu_reset)
{
    if (ctx != NULL)
    {
        ctx->ecu_reset = ecu_reset;
    }
}

void uds_seed_entropy(uds_context_t *ctx, uint32_t entropy)
{
    if (ctx != NULL)
    {
        ctx->seed_state ^= entropy;
    }
}

void uds_poll(uds_context_t *ctx, uint32_t now_ms)
{
    if (ctx == NULL)
    {
        return;
    }

    /*
     * Fin du verrouillage anti-force-brute. La soustraction non signee
     * reste correcte au repli de l'horloge 32 bits.
     */
    if ((ctx->locked_out != 0u) &&
        ((uint32_t)(now_ms - ctx->lockout_until_ms) < 0x80000000u))
    {
        ctx->locked_out      = 0u;
        ctx->failed_attempts = 0u;
    }

    /*
     * S3server : sans activite, une session privilegiee retombe en
     * session par defaut et la securite se reverrouille. Une session
     * ouverte que plus personne ne surveille est une session a fermer.
     */
    if (ctx->session != UDS_SESSION_DEFAULT)
    {
        if ((uint32_t)(now_ms - ctx->last_activity_ms) >=
            UDS_S3_SERVER_TIMEOUT_MS)
        {
            ctx->session        = UDS_SESSION_DEFAULT;
            ctx->security_level = UDS_SECURITY_LOCKED;
            ctx->seed_pending   = 0u;
        }
    }
}

uds_result_t uds_handle_request(uds_context_t *ctx,
                                const uint8_t *request,
                                uint16_t request_len,
                                uint32_t now_ms,
                                uint8_t *response,
                                uint16_t response_capacity,
                                uint16_t *response_len)
{
    uint8_t sid;
    const service_rule_t *rule;

    if ((ctx == NULL) || (request == NULL) ||
        (response == NULL) || (response_len == NULL))
    {
        return UDS_ERR_NULL_POINTER;
    }

    /*
     * Les echeances sont evaluees AVANT de traiter la requete : une
     * session expiree ne doit pas etre sauvee par la requete meme qui
     * arrive trop tard.
     */
    uds_poll(ctx, now_ms);

    /*
     * Une requete vide n'a pas de SID. Impossible de fabriquer une
     * reponse negative exploitable : on se tait plutot que d'inventer
     * un SID dans l'echo.
     */
    if (request_len == 0u)
    {
        *response_len = 0u;
        return UDS_NO_RESPONSE;
    }

    sid = request[0];

    /* --- Politique d'acces, avant tout traitement du contenu --- */
    rule = find_rule(sid);

    if (rule == NULL)
    {
        return make_negative_response(sid, UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }

    if ((rule->requires_extended_session != 0u) &&
        (ctx->session == UDS_SESSION_DEFAULT))
    {
        return make_negative_response(
            sid, UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
            response, response_capacity, response_len);
    }

    if ((rule->requires_security_unlock != 0u) &&
        (ctx->security_level == UDS_SECURITY_LOCKED))
    {
        return make_negative_response(sid, UDS_NRC_SECURITY_ACCESS_DENIED,
                                      response, response_capacity,
                                      response_len);
    }

    /*
     * La requete est recevable : elle repousse l'echeance S3server.
     * Fait apres les controles d'acces, pour qu'une requete refusee ne
     * maintienne pas une session ouverte gratuitement.
     */
    ctx->last_activity_ms = now_ms;

    switch (sid)
    {
    case UDS_SID_DIAGNOSTIC_SESSION_CONTROL:
        return handle_diagnostic_session_control(ctx, request, request_len,
                                                 response, response_capacity,
                                                 response_len);

    case UDS_SID_ECU_RESET:
        return handle_ecu_reset(ctx, request, request_len,
                                response, response_capacity, response_len);

    case UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION:
        return handle_clear_diagnostic_information(ctx, request, request_len,
                                                   response, response_capacity,
                                                   response_len);

    case UDS_SID_READ_DTC_INFORMATION:
        return handle_read_dtc_information(ctx, request, request_len,
                                           response, response_capacity,
                                           response_len);

    case UDS_SID_READ_DATA_BY_IDENTIFIER:
        return handle_read_data_by_identifier(ctx, request, request_len,
                                              response, response_capacity,
                                              response_len);

    case UDS_SID_SECURITY_ACCESS:
        return handle_security_access(ctx, request, request_len, now_ms,
                                      response, response_capacity,
                                      response_len);

    case UDS_SID_TESTER_PRESENT:
        return handle_tester_present(ctx, request, request_len,
                                     response, response_capacity,
                                     response_len);

    default:
        /* Inatteignable : find_rule aurait deja refuse. */
        return make_negative_response(sid, UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }
}
