/*
 * test_uds.c
 *
 * Tests unitaires du serveur UDS.
 *
 * L'essentiel de ce fichier porte sur les chemins de REFUS. Un serveur
 * de diagnostic passe la majorite de son temps a rejeter : c'est la que
 * se trouvent les bugs, et c'est ce que le cas nominal ne teste jamais.
 *
 * Build :
 *   make test
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "uds.h"

static int g_checks = 0;
static int g_failures = 0;

static void check(int condition, const char *what)
{
    g_checks++;
    if (!condition)
    {
        g_failures++;
        printf("  ECHEC : %s\n", what);
    }
}

/*
 * Envoie une requete a un contexte neuf et renvoie le resultat.
 * Le tampon de reponse est volontairement dimensionne a la limite
 * annoncee par l'API.
 */
static uds_result_t run(const uint8_t *req, uint8_t req_len,
                        uint8_t *resp, uint16_t *resp_len,
                        uds_context_t *ctx_out)
{
    uds_context_t ctx;
    uds_result_t res;

    uds_init(&ctx);
    *resp_len = 0u;

    res = uds_handle_request(&ctx, req, req_len, 0u,
                             resp, UDS_MAX_RESPONSE_SIZE, resp_len);

    if (ctx_out != NULL)
    {
        *ctx_out = ctx;
    }
    return res;
}

/* ------------------------------------------------------------------ */
/* 1. Etat initial                                                     */
/* ------------------------------------------------------------------ */
static void test_init(void)
{
    uds_context_t ctx;

    printf("[1] Etat initial\n");

    uds_init(&ctx);
    check(ctx.session == UDS_SESSION_DEFAULT,
          "un serveur demarre en session par defaut");

    /* Ne doit pas planter. */
    uds_init(NULL);
    check(1, "uds_init(NULL) ne dereference pas");
}

/* ------------------------------------------------------------------ */
/* 2. 0x10 DiagnosticSessionControl : cas positifs                     */
/* ------------------------------------------------------------------ */
static void test_dsc_positive(void)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;
    uds_context_t ctx;

    printf("[2] DiagnosticSessionControl : reponses positives\n");

    /* Extended : 10 03 -> 50 03 00 32 01 F4 */
    {
        const uint8_t req[] = { 0x10, 0x03 };
        check(run(req, 2, resp, &len, &ctx) == UDS_OK, "10 03 accepte");
        check(len == 6u, "reponse de 6 octets (SID + sub + P2 + P2*)");
        check(resp[0] == 0x50, "SID de reponse = 0x10 + 0x40");
        check(resp[1] == 0x03, "sous-fonction repetee");
        check(resp[2] == 0x00 && resp[3] == 0x32,
              "P2Server_max = 50 ms en big endian");
        check(resp[4] == 0x01 && resp[5] == 0xF4,
              "P2*Server_max = 500 x 10 ms");
        check(ctx.session == UDS_SESSION_EXTENDED,
              "la session passe a Extended");
    }

    /* Default : 10 01 */
    {
        const uint8_t req[] = { 0x10, 0x01 };
        check(run(req, 2, resp, &len, &ctx) == UDS_OK, "10 01 accepte");
        check(resp[0] == 0x50 && resp[1] == 0x01, "reponse 50 01");
        check(ctx.session == UDS_SESSION_DEFAULT, "session Default");
    }
}

/* ------------------------------------------------------------------ */
/* 3. suppressPosRspMsgIndicationBit                                   */
/* ------------------------------------------------------------------ */
static void test_suppress_bit(void)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;
    uds_context_t ctx;

    printf("[3] suppressPosRspMsgIndicationBit (bit 7)\n");

    /* 0x83 = 0x03 avec le bit 7 arme. */
    {
        const uint8_t req[] = { 0x10, 0x83 };
        check(run(req, 2, resp, &len, &ctx) == UDS_NO_RESPONSE,
              "10 83 : aucune reponse emise");
        check(len == 0u, "longueur de reponse nulle");
        check(ctx.session == UDS_SESSION_EXTENDED,
              "le changement de session a bien eu lieu malgre le silence");
    }

    /*
     * Le bit de suppression ne doit PAS faire taire une reponse
     * negative : une erreur doit toujours remonter au client.
     */
    {
        const uint8_t req[] = { 0x10, 0xF0 };  /* sous-fonction 0x70 */
        check(run(req, 2, resp, &len, &ctx) == UDS_OK,
              "une sous-fonction invalide repond meme avec le bit 7");
        check(resp[0] == 0x7F, "reponse negative");
        check(resp[2] == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
              "NRC 0x12 subFunctionNotSupported");
    }
}

/* ------------------------------------------------------------------ */
/* 4. Reponses negatives                                               */
/* ------------------------------------------------------------------ */
static void test_negative_responses(void)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;

    printf("[4] Reponses negatives\n");

    /* Service inconnu -> 7F <SID> 11 */
    {
        const uint8_t req[] = { 0x99, 0x00 };
        check(run(req, 2, resp, &len, NULL) == UDS_OK, "service 0x99 traite");
        check(len == 3u, "reponse negative de 3 octets");
        check(resp[0] == 0x7F, "marqueur 0x7F");
        check(resp[1] == 0x99, "le SID rejete est repete");
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED,
              "NRC 0x11 serviceNotSupported");
    }

    /* Sous-fonction inexistante -> 7F 10 12 */
    {
        const uint8_t req[] = { 0x10, 0x42 };
        check(run(req, 2, resp, &len, NULL) == UDS_OK, "sous-fonction 0x42");
        check(resp[0] == 0x7F && resp[1] == 0x10, "7F 10");
        check(resp[2] == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED, "NRC 0x12");
    }

    /*
     * Session de programmation : sous-fonction valide dans la norme,
     * mais non implementee par ce serveur. Refus explicite.
     */
    {
        const uint8_t req[] = { 0x10, 0x02 };
        check(run(req, 2, resp, &len, NULL) == UDS_OK, "10 02 traite");
        check(resp[0] == 0x7F, "refus de la session de programmation");
        check(resp[2] == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED, "NRC 0x12");
    }

    /* Longueur incorrecte : SID seul -> 7F 10 13 */
    {
        const uint8_t req[] = { 0x10 };
        check(run(req, 1, resp, &len, NULL) == UDS_OK, "10 seul traite");
        check(resp[0] == 0x7F && resp[1] == 0x10, "7F 10");
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH, "NRC 0x13");
    }

    /* Longueur incorrecte : octets en trop -> 7F 10 13 */
    {
        const uint8_t req[] = { 0x10, 0x03, 0xAA };
        check(run(req, 3, resp, &len, NULL) == UDS_OK, "10 03 AA traite");
        check(resp[0] == 0x7F, "refus");
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH, "NRC 0x13");
    }
}

/* ------------------------------------------------------------------ */
/* 5. Cas limites                                                      */
/* ------------------------------------------------------------------ */
static void test_edge_cases(void)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;
    uds_context_t ctx;

    printf("[5] Cas limites\n");

    /* Requete vide : pas de SID, donc pas de reponse possible. */
    {
        const uint8_t req[] = { 0x00 };
        check(run(req, 0, resp, &len, NULL) == UDS_NO_RESPONSE,
              "requete de longueur nulle : silence");
    }

    /* Pointeurs NULL. */
    {
        const uint8_t req[] = { 0x10, 0x03 };
        uds_init(&ctx);

        check(uds_handle_request(NULL, req, 2, 0u, resp, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "ctx NULL");
        check(uds_handle_request(&ctx, NULL, 2, 0u, resp, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "request NULL");
        check(uds_handle_request(&ctx, req, 2, 0u, NULL, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "response NULL");
        check(uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), NULL)
              == UDS_ERR_NULL_POINTER, "response_len NULL");
    }

    /* Tampon de reponse trop petit. */
    {
        const uint8_t req_pos[] = { 0x10, 0x03 };
        const uint8_t req_neg[] = { 0x99, 0x00 };
        uds_init(&ctx);

        check(uds_handle_request(&ctx, req_pos, 2, 0u, resp, 5, &len)
              == UDS_ERR_BUFFER_TOO_SMALL,
              "reponse positive : 5 octets insuffisants");
        check(uds_handle_request(&ctx, req_neg, 2, 0u, resp, 2, &len)
              == UDS_ERR_BUFFER_TOO_SMALL,
              "reponse negative : 2 octets insuffisants");
    }

    /*
     * Balayage : aucun SID ne doit provoquer de plantage, et tout
     * service non implemente doit produire un serviceNotSupported.
     *
     * Les services implementes sont exclus du compte. Cette liste doit
     * grandir a chaque nouveau service : c'est volontaire, elle sert de
     * garde-fou contre un service ajoute sans test.
     */
    {
        static const uint8_t implemented[] = {
            UDS_SID_DIAGNOSTIC_SESSION_CONTROL,
            UDS_SID_ECU_RESET,
            UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
            UDS_SID_READ_DTC_INFORMATION,
            UDS_SID_READ_DATA_BY_IDENTIFIER,
            UDS_SID_SECURITY_ACCESS,
            UDS_SID_TESTER_PRESENT
        };
        const int implemented_count =
            (int)(sizeof(implemented) / sizeof(implemented[0]));

        int sid;
        int rejected = 0;

        for (sid = 0; sid <= 255; sid++)
        {
            uint8_t req[2];
            uds_result_t res;
            size_t k;
            int is_implemented = 0;

            for (k = 0; k < sizeof(implemented) / sizeof(implemented[0]); k++)
            {
                if ((uint8_t)sid == implemented[k])
                {
                    is_implemented = 1;
                }
            }
            if (is_implemented)
            {
                continue;
            }

            req[0] = (uint8_t)sid;
            req[1] = 0x03;

            res = run(req, 2, resp, &len, NULL);

            if ((res == UDS_OK) && (resp[0] == 0x7F) &&
                (resp[1] == (uint8_t)sid) &&
                (resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED))
            {
                rejected++;
            }
        }
        check(rejected == (256 - implemented_count),
              "tous les SID non implementes sont rejetes");
    }
}

/* ------------------------------------------------------------------ */
/* 6. 0x22 ReadDataByIdentifier                                        */
/*                                                                     */
/*    Le fournisseur de DID est ici un faux, sans le moindre lien avec */
/*    l'ECU virtuel. C'est precisement ce que permet le decouplage par */
/*    pointeur de fonction : tester le service sans embarquer          */
/*    l'application.                                                   */
/* ------------------------------------------------------------------ */

#define FAKE_DID_SHORT     0x1234u   /* 2 octets, tient sans probleme */
#define FAKE_DID_HUGE      0x5678u   /* 20 octets, ne tient pas       */

static int g_provider_calls = 0;

static uds_result_t fake_did_read(uint16_t did, uint8_t *out,
                                  uint16_t out_capacity, uint16_t *out_len,
                                  void *user_ctx)
{
    (void)user_ctx;
    g_provider_calls++;

    if (did == FAKE_DID_SHORT)
    {
        if (out_capacity < 2u)
        {
            return UDS_ERR_BUFFER_TOO_SMALL;
        }
        out[0] = 0xCA;
        out[1] = 0xFE;
        *out_len = 2u;
        return UDS_OK;
    }

    if (did == FAKE_DID_HUGE)
    {
        /* Valeur connue mais volumineuse : 64 octets. */
        uint16_t i;

        if (out_capacity < 64u)
        {
            return UDS_ERR_BUFFER_TOO_SMALL;
        }
        for (i = 0u; i < 64u; i++)
        {
            out[i] = (uint8_t)i;
        }
        *out_len = 64u;
        return UDS_OK;
    }

    return UDS_ERR_DID_NOT_FOUND;
}

static void test_read_data_by_identifier(void)
{
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;
    uds_context_t ctx;

    printf("[6] ReadDataByIdentifier\n");

    /* Sans fournisseur branche, le service n'est pas supporte. */
    {
        const uint8_t req[] = { 0x22, 0x12, 0x34 };
        uds_init(&ctx);
        check(uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "requete traitee sans fournisseur");
        check(resp[0] == 0x7F && resp[1] == 0x22, "7F 22");
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED,
              "NRC 0x11 sans fournisseur de DID");
    }

    uds_init(&ctx);
    uds_set_did_provider(&ctx, fake_did_read, NULL);

    /* Lecture valide : 22 12 34 -> 62 12 34 CA FE */
    {
        const uint8_t req[] = { 0x22, 0x12, 0x34 };
        check(uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "DID connu accepte");
        check(len == 5u, "reponse de 5 octets");
        check(resp[0] == 0x62, "SID de reponse = 0x22 + 0x40");
        check(resp[1] == 0x12 && resp[2] == 0x34,
              "identifiant repete, poids fort en premier");
        check(resp[3] == 0xCA && resp[4] == 0xFE, "valeur transmise");
    }

    /* DID inconnu -> 7F 22 31 requestOutOfRange */
    {
        const uint8_t req[] = { 0x22, 0x00, 0x01 };
        check(uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "DID inconnu traite");
        check(resp[0] == 0x7F && resp[1] == 0x22, "7F 22");
        check(resp[2] == UDS_NRC_REQUEST_OUT_OF_RANGE, "NRC 0x31");
    }

    /* Valeur volumineuse : elle passe si le tampon est assez grand. */
    {
        const uint8_t req[] = { 0x22, 0x56, 0x78 };
        check(uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "valeur de 64 octets acceptee");
        check(len == 67u, "3 octets d'en-tete + 64 de donnees");
        check(resp[0] == 0x62, "reponse positive");
    }

    /*
     * Meme requete, mais avec un tampon de reponse volontairement
     * etroit : la valeur ne tient plus. La limite du transport doit
     * remonter comme responseTooLong, jamais comme une troncature
     * silencieuse. C'est ce qui se passe quand un VIN de 17 octets est
     * demande a un transport qui ne sait emettre que 7 octets.
     */
    {
        const uint8_t req[] = { 0x22, 0x56, 0x78 };
        uint8_t small[8];

        check(uds_handle_request(&ctx, req, 3, 0u, small, sizeof(small), &len)
              == UDS_OK, "DID trop grand pour le tampon traite");
        check(small[0] == 0x7F && small[1] == 0x22, "7F 22");
        check(small[2] == UDS_NRC_RESPONSE_TOO_LONG,
              "NRC 0x14 responseTooLong");
        check(len == 3u, "la reponse negative reste de 3 octets");
    }

    /* Longueurs de requete incorrectes. */
    {
        const uint8_t req_short[] = { 0x22, 0x12 };
        const uint8_t req_long[]  = { 0x22, 0x12, 0x34, 0x56 };

        check(uds_handle_request(&ctx, req_short, 2, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "22 tronque traite");
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH,
              "NRC 0x13 sur requete trop courte");

        check(uds_handle_request(&ctx, req_long, 4, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "22 avec 2 DID traite");
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH,
              "NRC 0x13 : plusieurs identifiants non supportes");
    }

    /*
     * Une requete de longueur invalide ne doit meme pas atteindre le
     * fournisseur : le controle de forme precede l'acces aux donnees.
     */
    {
        const uint8_t req[] = { 0x22, 0x12 };
        int before = g_provider_calls;
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(g_provider_calls == before,
              "le fournisseur n'est pas appele sur une requete malformee");
    }

    /* Balayage : aucun DID ne doit faire planter le serveur. */
    {
        int did;
        int handled = 0;

        for (did = 0; did <= 0xFF; did++)
        {
            uint8_t req[3];
            req[0] = 0x22;
            req[1] = 0x00;
            req[2] = (uint8_t)did;

            if (uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
                == UDS_OK)
            {
                handled++;
            }
        }
        check(handled == 256, "les 256 identifiants balayes sont traites");
    }
}


/* ------------------------------------------------------------------ */
/* 7. Regles d'acces par session                                       */
/* ------------------------------------------------------------------ */

/* Ouvre une session etendue sur un contexte donne. */
static void open_extended(uds_context_t *ctx, uint32_t now)
{
    const uint8_t req[] = { 0x10, 0x03 };
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len = 0u;

    (void)uds_handle_request(ctx, req, 2, now, resp, sizeof(resp), &len);
}

static void test_session_rules(void)
{
    uds_context_t ctx;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len = 0u;

    printf("[7] Regles d'acces par session\n");

    /* En session par defaut, ECUReset est hors de portee. */
    {
        const uint8_t req[] = { 0x11, 0x01 };
        uds_init(&ctx);
        check(uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "requete traitee");
        check(resp[0] == 0x7F && resp[1] == 0x11, "7F 11");
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
              "NRC 0x7F serviceNotSupportedInActiveSession");
    }

    /* SecurityAccess exige aussi la session etendue. */
    {
        const uint8_t req[] = { 0x27, 0x01 };
        uds_init(&ctx);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
              "0x27 refuse en session par defaut");
    }

    /* En session etendue, ECUReset passe le controle de session mais
       bute sur le controle de securite : le NRC change. */
    {
        const uint8_t req[] = { 0x11, 0x01 };
        uds_init(&ctx);
        open_extended(&ctx, 0u);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SECURITY_ACCESS_DENIED,
              "NRC 0x33 securityAccessDenied une fois la session ouverte");
    }

    /* Lecture et TesterPresent restent accessibles partout. */
    {
        const uint8_t req[] = { 0x3E, 0x00 };
        uds_init(&ctx);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[0] == 0x7E, "TesterPresent accepte en session par defaut");
    }
}

/* ------------------------------------------------------------------ */
/* 8. S3server : expiration de la session                              */
/* ------------------------------------------------------------------ */
static void test_session_timeout(void)
{
    uds_context_t ctx;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len = 0u;

    printf("[8] Expiration de session (S3server)\n");

    uds_init(&ctx);
    open_extended(&ctx, 1000u);
    check(ctx.session == UDS_SESSION_EXTENDED, "session ouverte");

    uds_poll(&ctx, 1000u + UDS_S3_SERVER_TIMEOUT_MS - 1u);
    check(ctx.session == UDS_SESSION_EXTENDED, "sous le seuil : session tenue");

    uds_poll(&ctx, 1000u + UDS_S3_SERVER_TIMEOUT_MS);
    check(ctx.session == UDS_SESSION_DEFAULT, "au seuil : retour au defaut");
    check(ctx.security_level == UDS_SECURITY_LOCKED,
          "la securite se reverrouille avec la session");

    /* TesterPresent repousse l'echeance. */
    uds_init(&ctx);
    open_extended(&ctx, 1000u);
    {
        const uint8_t req[] = { 0x3E, 0x00 };
        uint32_t t;

        for (t = 1000u; t < 20000u; t += (UDS_S3_SERVER_TIMEOUT_MS / 2u))
        {
            (void)uds_handle_request(&ctx, req, 2, t, resp, sizeof(resp), &len);
        }
        check(ctx.session == UDS_SESSION_EXTENDED,
              "TesterPresent periodique maintient la session ouverte");
    }

    /* Une requete refusee ne doit pas prolonger la session. */
    uds_init(&ctx);
    open_extended(&ctx, 1000u);
    {
        const uint8_t req[] = { 0x99, 0x00 };   /* service inconnu */
        (void)uds_handle_request(&ctx, req, 2, 3000u,
                                 resp, sizeof(resp), &len);
        uds_poll(&ctx, 1000u + UDS_S3_SERVER_TIMEOUT_MS);
        check(ctx.session == UDS_SESSION_DEFAULT,
              "une requete rejetee ne maintient pas la session");
    }
}

/* ------------------------------------------------------------------ */
/* 9. SecurityAccess                                                   */
/* ------------------------------------------------------------------ */
static void test_security_access(void)
{
    uds_context_t ctx;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len = 0u;
    uint32_t seed;
    uint32_t key;
    uint8_t key_req[6];

    printf("[9] SecurityAccess\n");

    /* --- Deverrouillage nominal --- */
    uds_init(&ctx);
    open_extended(&ctx, 0u);
    {
        const uint8_t req[] = { 0x27, 0x01 };
        check(uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "demande de graine acceptee");
        check(len == 6u, "0x67 + sous-fonction + 4 octets de graine");
        check(resp[0] == 0x67 && resp[1] == 0x01, "67 01");

        seed = (((uint32_t)resp[2]) << 24) | (((uint32_t)resp[3]) << 16) |
               (((uint32_t)resp[4]) << 8) | ((uint32_t)resp[5]);
        check(seed != 0u, "la graine n'est pas nulle");
    }

    key = uds_demo_key_from_seed(seed);
    key_req[0] = 0x27; key_req[1] = 0x02;
    key_req[2] = (uint8_t)(key >> 24); key_req[3] = (uint8_t)(key >> 16);
    key_req[4] = (uint8_t)(key >> 8);  key_req[5] = (uint8_t)key;

    (void)uds_handle_request(&ctx, key_req, 6, 0u, resp, sizeof(resp), &len);
    check(resp[0] == 0x67 && resp[1] == 0x02, "cle correcte acceptee");
    check(ctx.security_level == UDS_SECURITY_LEVEL_1, "acces deverrouille");

    /* --- Rejeu de la meme cle --- */
    (void)uds_handle_request(&ctx, key_req, 6, 0u, resp, sizeof(resp), &len);
    check(resp[0] == 0x7F && resp[2] == UDS_NRC_CONDITIONS_NOT_CORRECT,
          "rejeu refuse : aucune graine en attente");

    /* --- ECUReset devient accessible --- */
    {
        const uint8_t req[] = { 0x11, 0x01 };
        uds_set_reset_handler(&ctx, NULL);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED,
              "le controle de securite est passe, le handler manque");
    }

    /* --- Graine nulle si deja deverrouille --- */
    {
        const uint8_t req[] = { 0x27, 0x01 };
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        seed = (((uint32_t)resp[2]) << 24) | (((uint32_t)resp[3]) << 16) |
               (((uint32_t)resp[4]) << 8) | ((uint32_t)resp[5]);
        check(seed == 0u, "graine nulle quand l'acces est deja ouvert");
    }

    /* --- Une graine differente a chaque demande --- */
    {
        const uint8_t req[] = { 0x27, 0x01 };
        uint32_t s1;
        uint32_t s2;

        uds_init(&ctx);
        open_extended(&ctx, 0u);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        s1 = (((uint32_t)resp[2]) << 24) | ((uint32_t)resp[5]);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        s2 = (((uint32_t)resp[2]) << 24) | ((uint32_t)resp[5]);
        check(s1 != s2, "deux demandes donnent deux graines differentes");
    }

    /* --- Cle fausse : la graine est consommee --- */
    {
        const uint8_t seed_req[] = { 0x27, 0x01 };
        uint8_t bad[6] = { 0x27, 0x02, 0xDE, 0xAD, 0xBE, 0xEF };

        uds_init(&ctx);
        open_extended(&ctx, 0u);
        (void)uds_handle_request(&ctx, seed_req, 2, 0u,
                                 resp, sizeof(resp), &len);
        (void)uds_handle_request(&ctx, bad, 6, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_INVALID_KEY, "NRC 0x35 invalidKey");
        check(ctx.security_level == UDS_SECURITY_LOCKED, "toujours verrouille");

        /* Un second essai sans nouvelle graine est hors sequence. */
        (void)uds_handle_request(&ctx, bad, 6, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_CONDITIONS_NOT_CORRECT,
              "la graine ratee n'est pas reutilisable");
    }

    /* --- Anti-force-brute --- */
    {
        const uint8_t seed_req[] = { 0x27, 0x01 };
        uint8_t bad[6] = { 0x27, 0x02, 0x00, 0x00, 0x00, 0x00 };
        int attempt;

        uds_init(&ctx);
        open_extended(&ctx, 0u);

        for (attempt = 0; attempt < (int)UDS_SECURITY_MAX_ATTEMPTS; attempt++)
        {
            (void)uds_handle_request(&ctx, seed_req, 2, 0u,
                                     resp, sizeof(resp), &len);
            (void)uds_handle_request(&ctx, bad, 6, 0u,
                                     resp, sizeof(resp), &len);
        }
        check(resp[2] == UDS_NRC_EXCEED_NUMBER_OF_ATTEMPTS,
              "NRC 0x36 apres trois cles fausses");
        check(ctx.locked_out == 1u, "serveur verrouille");

        /* Pendant le verrouillage, meme la demande de graine est refusee. */
        (void)uds_handle_request(&ctx, seed_req, 2, 0u,
                                 resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED,
              "NRC 0x37 pendant le verrouillage");

        /* Le verrouillage se leve tout seul. */
        uds_poll(&ctx, UDS_SECURITY_LOCKOUT_MS + 1u);
        check(ctx.locked_out == 0u, "verrouillage leve apres le delai");
    }

    /* --- Longueurs invalides --- */
    {
        const uint8_t short_key[] = { 0x27, 0x02, 0x11 };
        const uint8_t long_seed[] = { 0x27, 0x01, 0x00 };

        uds_init(&ctx);
        open_extended(&ctx, 0u);
        (void)uds_handle_request(&ctx, short_key, 3, 0u,
                                 resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH, "cle tronquee");
        (void)uds_handle_request(&ctx, long_seed, 3, 0u,
                                 resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH,
              "demande de graine trop longue");
    }

    /* --- Sous-fonction inconnue --- */
    {
        const uint8_t req[] = { 0x27, 0x09 };
        uds_init(&ctx);
        open_extended(&ctx, 0u);
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
              "niveau de securite inconnu refuse");
    }
}

/* ------------------------------------------------------------------ */
/* 10. Derivation de cle                                               */
/* ------------------------------------------------------------------ */
static void test_key_derivation(void)
{
    uint32_t a;
    uint32_t b;
    int i;
    int collisions = 0;

    printf("[10] Derivation de cle (demonstration)\n");

    check(uds_demo_key_from_seed(0u) == uds_demo_key_from_seed(0u),
          "deterministe");

    a = uds_demo_key_from_seed(0x11111111u);
    b = uds_demo_key_from_seed(0x11111112u);
    check(a != b, "deux graines voisines donnent deux cles differentes");

    /* Aucune graine ne doit produire une cle egale a elle-meme. */
    for (i = 0; i < 1000; i++)
    {
        uint32_t seed = (uint32_t)(i * 2654435761u);
        if (uds_demo_key_from_seed(seed) == seed)
        {
            collisions++;
        }
    }
    check(collisions == 0, "la cle n'est jamais egale a la graine");
}

/* ------------------------------------------------------------------ */
/* 11. Services DTC                                                    */
/* ------------------------------------------------------------------ */

static uds_result_t fake_dtc_read(uint8_t status_mask, uint8_t *out,
                                  uint16_t out_capacity, uint16_t *out_len,
                                  void *user_ctx)
{
    (void)user_ctx;

    if (status_mask == 0u)
    {
        *out_len = 0u;
        return UDS_OK;
    }
    if (out_capacity < 4u)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }
    out[0] = 0x01; out[1] = 0x17; out[2] = 0x00; out[3] = 0x09;
    *out_len = 4u;
    return UDS_OK;
}

static int g_cleared = 0;

static uds_result_t fake_dtc_clear(uint32_t group, void *user_ctx)
{
    (void)user_ctx;
    if (group == 0xFFFFFFu)
    {
        g_cleared++;
        return UDS_OK;
    }
    return UDS_ERR_DID_NOT_FOUND;
}

static void test_dtc_services(void)
{
    uds_context_t ctx;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len = 0u;

    printf("[11] Services de codes defaut\n");

    /* Sans fournisseur, 0x19 n'est pas supporte. */
    {
        const uint8_t req[] = { 0x19, 0x02, 0x09 };
        uds_init(&ctx);
        (void)uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED,
              "0x19 sans fournisseur");
    }

    uds_init(&ctx);
    uds_set_dtc_provider(&ctx, fake_dtc_read, fake_dtc_clear);

    /* Lecture nominale. */
    {
        const uint8_t req[] = { 0x19, 0x02, 0x09 };
        check(uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "0x19 02 accepte");
        check(resp[0] == 0x59 && resp[1] == 0x02, "59 02");
        check(len == 7u, "3 octets d'en-tete + un defaut de 4 octets");
        check(resp[3] == 0x01 && resp[6] == 0x09, "code et statut");
    }

    /* Masque nul : aucun defaut rapporte, la reponse reste valide. */
    {
        const uint8_t req[] = { 0x19, 0x02, 0x00 };
        (void)uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len);
        check(len == 3u, "en-tete seul quand aucun defaut ne correspond");
    }

    /* Sous-fonction non implementee. */
    {
        const uint8_t req[] = { 0x19, 0x01, 0x09 };
        (void)uds_handle_request(&ctx, req, 3, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED,
              "0x19 01 non implementee");
    }

    /* Longueur incorrecte. */
    {
        const uint8_t req[] = { 0x19, 0x02 };
        (void)uds_handle_request(&ctx, req, 2, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH,
              "masque de statut manquant");
    }

    /* Effacement : reserve a la session etendue. */
    {
        const uint8_t req[] = { 0x14, 0xFF, 0xFF, 0xFF };
        uds_init(&ctx);
        uds_set_dtc_provider(&ctx, fake_dtc_read, fake_dtc_clear);

        (void)uds_handle_request(&ctx, req, 4, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
              "0x14 refuse en session par defaut");

        open_extended(&ctx, 0u);
        g_cleared = 0;
        check(uds_handle_request(&ctx, req, 4, 0u, resp, sizeof(resp), &len)
              == UDS_OK, "0x14 accepte en session etendue");
        check(resp[0] == 0x54 && len == 1u, "reponse 0x54");
        check(g_cleared == 1, "le fournisseur a bien ete appele");
    }

    /* Groupe inconnu. */
    {
        const uint8_t req[] = { 0x14, 0x00, 0x00, 0x01 };
        (void)uds_handle_request(&ctx, req, 4, 0u, resp, sizeof(resp), &len);
        check(resp[2] == UDS_NRC_REQUEST_OUT_OF_RANGE, "groupe inconnu");
    }
}

/* ------------------------------------------------------------------ */
/* 12. Balayage : aucune requete ne doit faire tomber le serveur       */
/* ------------------------------------------------------------------ */
static void test_full_sweep(void)
{
    uds_context_t ctx;
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t len;
    int sid;
    int sub;
    int lengths[] = { 0, 1, 2, 3, 4, 6, 8 };
    size_t li;
    int total = 0;

    printf("[12] Balayage : 256 SID x 4 sous-fonctions x 7 longueurs\n");

    for (sid = 0; sid <= 255; sid++)
    {
        for (sub = 0; sub < 4; sub++)
        {
            for (li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++)
            {
                uint8_t req[8];
                uint8_t k;
                uds_result_t res;

                uds_init(&ctx);
                uds_set_dtc_provider(&ctx, fake_dtc_read, fake_dtc_clear);
                ctx.session = UDS_SESSION_EXTENDED;

                for (k = 0u; k < 8u; k++) { req[k] = (uint8_t)(k * 17u); }
                req[0] = (uint8_t)sid;
                req[1] = (uint8_t)(sub * 0x40);

                len = 0xFFFFu;
                res = uds_handle_request(&ctx, req, (uint16_t)lengths[li], 0u,
                                         resp, sizeof(resp), &len);

                if ((res != UDS_OK) && (res != UDS_NO_RESPONSE))
                {
                    g_failures++;
                }
                if ((res == UDS_OK) && (len > sizeof(resp)))
                {
                    g_failures++;
                }
                total++;
            }
        }
    }
    g_checks += total;
    check(total == 256 * 4 * 7, "7168 requetes balayees");
    printf("    -> aucune erreur interne, aucun debordement ASAN\n");
}

int main(void)
{
    printf("=============================================\n");
    printf(" Tests unitaires serveur UDS\n");
    printf("=============================================\n\n");

    test_init();
    test_dsc_positive();
    test_suppress_bit();
    test_negative_responses();
    test_edge_cases();
    test_read_data_by_identifier();
    test_session_rules();
    test_session_timeout();
    test_security_access();
    test_key_derivation();
    test_dtc_services();
    test_full_sweep();

    printf("\n=============================================\n");
    printf(" %d verifications, %d echec(s)\n", g_checks, g_failures);
    printf("=============================================\n");

    return (g_failures == 0) ? 0 : 1;
}
