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
                                           uint8_t response_capacity,
                                           uint8_t *response_len)
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
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_capacity,
    uint8_t *response_len)
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
/* Point d'entree                                                      */
/* ------------------------------------------------------------------ */

void uds_init(uds_context_t *ctx)
{
    if (ctx != NULL)
    {
        ctx->session = UDS_SESSION_DEFAULT;
    }
}

uds_result_t uds_handle_request(uds_context_t *ctx,
                                const uint8_t *request,
                                uint8_t request_len,
                                uint8_t *response,
                                uint8_t response_capacity,
                                uint8_t *response_len)
{
    uint8_t sid;

    if ((ctx == NULL) || (request == NULL) ||
        (response == NULL) || (response_len == NULL))
    {
        return UDS_ERR_NULL_POINTER;
    }

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

    switch (sid)
    {
    case UDS_SID_DIAGNOSTIC_SESSION_CONTROL:
        return handle_diagnostic_session_control(ctx, request, request_len,
                                                 response, response_capacity,
                                                 response_len);

    default:
        return make_negative_response(sid,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }
}
