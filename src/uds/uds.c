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
/* Point d'entree                                                      */
/* ------------------------------------------------------------------ */

void uds_init(uds_context_t *ctx)
{
    if (ctx != NULL)
    {
        ctx->session  = UDS_SESSION_DEFAULT;
        ctx->did_read = NULL;
        ctx->user_ctx = NULL;
    }
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

uds_result_t uds_handle_request(uds_context_t *ctx,
                                const uint8_t *request,
                                uint16_t request_len,
                                uint8_t *response,
                                uint16_t response_capacity,
                                uint16_t *response_len)
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

    case UDS_SID_READ_DATA_BY_IDENTIFIER:
        return handle_read_data_by_identifier(ctx, request, request_len,
                                              response, response_capacity,
                                              response_len);

    default:
        return make_negative_response(sid,
                                      UDS_NRC_SERVICE_NOT_SUPPORTED,
                                      response, response_capacity,
                                      response_len);
    }
}
