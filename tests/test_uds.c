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

    res = uds_handle_request(&ctx, req, req_len,
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

        check(uds_handle_request(NULL, req, 2, resp, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "ctx NULL");
        check(uds_handle_request(&ctx, NULL, 2, resp, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "request NULL");
        check(uds_handle_request(&ctx, req, 2, NULL, sizeof(resp), &len)
              == UDS_ERR_NULL_POINTER, "response NULL");
        check(uds_handle_request(&ctx, req, 2, resp, sizeof(resp), NULL)
              == UDS_ERR_NULL_POINTER, "response_len NULL");
    }

    /* Tampon de reponse trop petit. */
    {
        const uint8_t req_pos[] = { 0x10, 0x03 };
        const uint8_t req_neg[] = { 0x99, 0x00 };
        uds_init(&ctx);

        check(uds_handle_request(&ctx, req_pos, 2, resp, 5, &len)
              == UDS_ERR_BUFFER_TOO_SMALL,
              "reponse positive : 5 octets insuffisants");
        check(uds_handle_request(&ctx, req_neg, 2, resp, 2, &len)
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
            UDS_SID_READ_DATA_BY_IDENTIFIER
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
        check(uds_handle_request(&ctx, req, 3, resp, sizeof(resp), &len)
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
        check(uds_handle_request(&ctx, req, 3, resp, sizeof(resp), &len)
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
        check(uds_handle_request(&ctx, req, 3, resp, sizeof(resp), &len)
              == UDS_OK, "DID inconnu traite");
        check(resp[0] == 0x7F && resp[1] == 0x22, "7F 22");
        check(resp[2] == UDS_NRC_REQUEST_OUT_OF_RANGE, "NRC 0x31");
    }

    /* Valeur volumineuse : elle passe si le tampon est assez grand. */
    {
        const uint8_t req[] = { 0x22, 0x56, 0x78 };
        check(uds_handle_request(&ctx, req, 3, resp, sizeof(resp), &len)
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

        check(uds_handle_request(&ctx, req, 3, small, sizeof(small), &len)
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

        check(uds_handle_request(&ctx, req_short, 2, resp, sizeof(resp), &len)
              == UDS_OK, "22 tronque traite");
        check(resp[2] == UDS_NRC_INCORRECT_MESSAGE_LENGTH,
              "NRC 0x13 sur requete trop courte");

        check(uds_handle_request(&ctx, req_long, 4, resp, sizeof(resp), &len)
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
        (void)uds_handle_request(&ctx, req, 2, resp, sizeof(resp), &len);
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

            if (uds_handle_request(&ctx, req, 3, resp, sizeof(resp), &len)
                == UDS_OK)
            {
                handled++;
            }
        }
        check(handled == 256, "les 256 identifiants balayes sont traites");
    }
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

    printf("\n=============================================\n");
    printf(" %d verifications, %d echec(s)\n", g_checks, g_failures);
    printf("=============================================\n");

    return (g_failures == 0) ? 0 : 1;
}
