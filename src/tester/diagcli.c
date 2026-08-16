/*
 * diagcli.c
 *
 * Client de diagnostic interactif.
 *
 * Le tester scripte deroule toujours le meme scenario ; celui-ci se
 * pilote a la main, ce qui permet d'explorer l'ECU pendant une
 * demonstration ou de reproduire un cas precis sans recompiler.
 *
 * Il lit aussi son entree standard, donc un scenario peut lui etre
 * fourni par un tube. Dans ce cas chaque commande est reaffichee, pour
 * qu'un enregistrement reste lisible.
 *
 * Usage :
 *   ./build/diagcli
 *   cat scenario.txt | ./build/diagcli
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "can_socket.h"
#include "diag_link.h"
#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"

#define CAN_ID_TESTER_TO_ECU   0x7E0u
#define CAN_ID_ECU_TO_TESTER   0x7E8u
#define CAN_INTERFACE          "vcan0"
#define RX_TICK_MS             50u
#define RESPONSE_TIMEOUT_MS    2000u

#define MAX_LINE               256
#define MAX_PAYLOAD            64

static can_socket_t g_sock;
static diag_link_t  g_link;

/* Etat suivi cote client, pour l'invite. */
static const char *g_session  = "DEFAULT";
static const char *g_security = "LOCKED";

/* Derniere graine recue, pour que "key" puisse repondre. */
static uint32_t g_last_seed = 0u;
static int      g_have_seed = 0;

static int g_interactive = 0;

/* ------------------------------------------------------------------ */
/* Affichage                                                           */
/* ------------------------------------------------------------------ */

static void print_hex(const uint8_t *data, uint16_t len)
{
    uint16_t i;
    for (i = 0u; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

static void prompt(void)
{
    printf("\n[%s | %s] > ", g_session, g_security);
    fflush(stdout);
}

static void show_response(const uint8_t *p, uint16_t len)
{
    printf("  RX  ");
    print_hex(p, len);
    printf("\n");

    if (len == 0u)
    {
        printf("      reponse vide\n");
        return;
    }

    /* Reponse negative : a tester avant tout le reste. */
    if ((len == UDS_NEGATIVE_RESPONSE_LEN) &&
        (p[0] == UDS_NEGATIVE_RESPONSE_SID))
    {
        printf("      REFUS  %s -> NRC 0x%02X  %s\n",
               uds_sid_to_string(p[1]), p[2], uds_nrc_to_string(p[2]));
        return;
    }

    switch (p[0])
    {
    case 0x50:
        g_session = (p[1] == (uint8_t)UDS_SESSION_EXTENDED)
                        ? "EXTENDED" : "DEFAULT";
        if (p[1] != (uint8_t)UDS_SESSION_EXTENDED)
        {
            g_security = "LOCKED";
        }
        printf("      OK     session %s\n", g_session);
        if (len >= 6u)
        {
            printf("             P2 %u ms, P2* %u ms\n",
                   (unsigned)((p[2] << 8) | p[3]),
                   (unsigned)(((p[4] << 8) | p[5]) * 10));
        }
        break;

    case 0x51:
        g_session  = "DEFAULT";
        g_security = "LOCKED";
        printf("      OK     calculateur reinitialise\n");
        break;

    case 0x54:
        printf("      OK     defauts effaces\n");
        break;

    case 0x59:
    {
        uint16_t count = (len >= 3u) ? (uint16_t)((len - 3u) / 4u) : 0u;
        uint16_t i;
        printf("      OK     %u code(s) defaut\n", count);
        for (i = 0u; i < count; i++)
        {
            const uint8_t *r = &p[3u + (i * 4u)];
            uint32_t code = ((uint32_t)r[0] << 16) |
                            ((uint32_t)r[1] << 8) | (uint32_t)r[2];
            printf("             %06X  statut %02X  %s\n",
                   code, r[3], ecu_data_dtc_to_string(code));
        }
        break;
    }

    case 0x62:
    {
        uint16_t did = (uint16_t)(((uint16_t)p[1] << 8) | p[2]);
        uint16_t dlen = (uint16_t)(len - 3u);
        uint16_t i;
        int printable = 1;

        printf("      OK     DID %04X  %s\n", did,
               ecu_data_did_to_string(did));
        printf("             ");
        print_hex(&p[3], dlen);

        for (i = 0u; i < dlen; i++)
        {
            if ((p[3 + i] < 0x20u) || (p[3 + i] > 0x7Eu)) { printable = 0; }
        }

        if ((did == DID_ENGINE_RPM) && (dlen == 2u))
        {
            printf(" = %u tr/min", (unsigned)((p[3] << 8) | p[4]));
        }
        else if ((did == DID_VEHICLE_SPEED) && (dlen == 1u))
        {
            printf(" = %u km/h", p[3]);
        }
        else if ((did == DID_COOLANT_TEMPERATURE) && (dlen == 2u))
        {
            printf(" = %d C", (int)(int16_t)((p[3] << 8) | p[4]));
        }
        else if ((did == DID_BATTERY_VOLTAGE) && (dlen == 2u))
        {
            unsigned mv = (unsigned)((p[3] << 8) | p[4]);
            printf(" = %u.%03u V", mv / 1000u, mv % 1000u);
        }
        else if ((printable != 0) && (dlen > 0u))
        {
            printf(" = \"");
            for (i = 0u; i < dlen; i++) { printf("%c", (char)p[3 + i]); }
            printf("\"");
        }
        printf("\n");
        break;
    }

    case 0x67:
        if ((p[1] == UDS_SECURITY_REQUEST_SEED) && (len >= 6u))
        {
            g_last_seed = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16) |
                          ((uint32_t)p[4] << 8) | (uint32_t)p[5];
            g_have_seed = 1;
            printf("      OK     graine %08X\n", g_last_seed);
            printf("             cle attendue : %08X   (\"key\" pour l'envoyer)\n",
                   uds_demo_key_from_seed(g_last_seed));
        }
        else
        {
            g_security = "UNLOCKED";
            printf("      OK     ACCES DEVERROUILLE\n");
        }
        break;

    case 0x7E:
        printf("      OK     TesterPresent\n");
        break;

    default:
        printf("      reponse non interpretee\n");
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Echange                                                             */
/* ------------------------------------------------------------------ */

static void send_uds(const uint8_t *payload, uint16_t len)
{
    const uint8_t *resp = NULL;
    uint16_t resp_len = 0u;
    int r;

    printf("  TX  ");
    print_hex(payload, len);
    printf("\n");

    if (diag_link_send(&g_link, payload, len) != 0)
    {
        printf("      ECHEC emission : %s\n",
               isotp_result_to_string(g_link.last_error));
        return;
    }

    r = diag_link_recv(&g_link, &resp, &resp_len, RESPONSE_TIMEOUT_MS);

    if (r < 0)
    {
        printf("      ERREUR de reception\n");
        return;
    }
    if (r == 0)
    {
        printf("      AUCUNE REPONSE (%u ms)\n", RESPONSE_TIMEOUT_MS);
        return;
    }

    show_response(resp, resp_len);
}

/* ------------------------------------------------------------------ */
/* Table des identifiants nommes                                       */
/* ------------------------------------------------------------------ */

typedef struct
{
    const char *name;
    uint16_t    did;
} did_alias_t;

static const did_alias_t DID_ALIASES[] = {
    { "vin",      DID_VIN                  },
    { "sw",       DID_ECU_SOFTWARE_VERSION },
    { "serial",   DID_ECU_SERIAL_NUMBER    },
    { "rpm",      DID_ENGINE_RPM           },
    { "speed",    DID_VEHICLE_SPEED        },
    { "temp",     DID_COOLANT_TEMPERATURE  },
    { "battery",  DID_BATTERY_VOLTAGE      }
};

#define DID_ALIAS_COUNT (sizeof(DID_ALIASES) / sizeof(DID_ALIASES[0]))

/* Renvoie 1 si l'argument a pu etre resolu en identifiant. */
static int resolve_did(const char *arg, uint16_t *out)
{
    size_t i;
    char *end = NULL;
    unsigned long value;

    for (i = 0u; i < DID_ALIAS_COUNT; i++)
    {
        if (strcmp(arg, DID_ALIASES[i].name) == 0)
        {
            *out = DID_ALIASES[i].did;
            return 1;
        }
    }

    value = strtoul(arg, &end, 16);
    if ((end != arg) && (*end == '\0') && (value <= 0xFFFFu))
    {
        *out = (uint16_t)value;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Commandes                                                           */
/* ------------------------------------------------------------------ */

static void cmd_help(void)
{
    printf("\n");
    printf("  session default|extended    DiagnosticSessionControl (0x10)\n");
    printf("  read <nom|DID>              ReadDataByIdentifier     (0x22)\n");
    printf("      noms : vin sw serial rpm speed temp battery\n");
    printf("  dtc                         ReadDTCInformation       (0x19)\n");
    printf("  clear                       ClearDiagnosticInfo      (0x14)\n");
    printf("  seed                        SecurityAccess, graine   (0x27 01)\n");
    printf("  key [hex8]                  SecurityAccess, cle      (0x27 02)\n");
    printf("  reset                       ECUReset                 (0x11)\n");
    printf("  present                     TesterPresent            (0x3E)\n");
    printf("  raw <octets hex>            requete UDS brute\n");
    printf("  stats                       compteurs ISO-TP locaux\n");
    printf("  help                        cette aide\n");
    printf("  quit                        sortir\n");
}

static void cmd_stats(void)
{
    printf("\n  Reception ISO-TP\n");
    printf("    trames recues        : %u\n", g_link.rx.stat_frames);
    printf("    messages reassembles : %u\n", g_link.rx.stat_messages);
    printf("    trames rejetees      : %u\n", g_link.rx.stat_rejected);
    printf("    erreurs de sequence  : %u\n", g_link.rx.stat_sequence_errors);
    printf("    delais expires       : %u\n", g_link.rx.stat_timeouts);
    printf("  Emission ISO-TP\n");
    printf("    messages emis        : %u\n", g_link.tx.stat_messages);
    printf("    trames emises        : %u\n", g_link.tx.stat_frames);
}

/* Decoupe une ligne en mots. Renvoie le nombre de mots. */
static int split(char *line, char **argv, int max)
{
    int argc = 0;
    char *p = line;

    while ((*p != '\0') && (argc < max))
    {
        while ((*p == ' ') || (*p == '\t')) { p++; }
        if (*p == '\0') { break; }

        argv[argc++] = p;

        while ((*p != '\0') && (*p != ' ') && (*p != '\t')) { p++; }
        if (*p != '\0') { *p = '\0'; p++; }
    }
    return argc;
}

/* Renvoie 0 pour continuer, 1 pour sortir. */
static int execute(int argc, char **argv)
{
    if (argc == 0) { return 0; }

    if ((strcmp(argv[0], "quit") == 0) || (strcmp(argv[0], "exit") == 0))
    {
        return 1;
    }

    if (strcmp(argv[0], "help") == 0) { cmd_help(); return 0; }
    if (strcmp(argv[0], "stats") == 0) { cmd_stats(); return 0; }

    if (strcmp(argv[0], "session") == 0)
    {
        uint8_t req[2] = { UDS_SID_DIAGNOSTIC_SESSION_CONTROL, 0x01 };

        if ((argc > 1) && (strcmp(argv[1], "extended") == 0))
        {
            req[1] = 0x03;
        }
        else if ((argc > 1) && (strcmp(argv[1], "programming") == 0))
        {
            req[1] = 0x02;
        }
        send_uds(req, 2u);
        return 0;
    }

    if (strcmp(argv[0], "read") == 0)
    {
        uint16_t did;
        uint8_t req[3];

        if (argc < 2)
        {
            printf("      usage : read <nom|DID hexa>\n");
            return 0;
        }
        if (resolve_did(argv[1], &did) == 0)
        {
            printf("      identifiant inconnu : %s\n", argv[1]);
            return 0;
        }

        req[0] = UDS_SID_READ_DATA_BY_IDENTIFIER;
        req[1] = (uint8_t)((did >> 8) & 0xFFu);
        req[2] = (uint8_t)(did & 0xFFu);
        send_uds(req, 3u);
        return 0;
    }

    if (strcmp(argv[0], "dtc") == 0)
    {
        uint8_t req[3] = { UDS_SID_READ_DTC_INFORMATION, 0x02, 0x09 };
        send_uds(req, 3u);
        return 0;
    }

    if (strcmp(argv[0], "clear") == 0)
    {
        uint8_t req[4] = { UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
                           0xFF, 0xFF, 0xFF };
        send_uds(req, 4u);
        return 0;
    }

    if (strcmp(argv[0], "seed") == 0)
    {
        uint8_t req[2] = { UDS_SID_SECURITY_ACCESS, UDS_SECURITY_REQUEST_SEED };
        send_uds(req, 2u);
        return 0;
    }

    if (strcmp(argv[0], "key") == 0)
    {
        uint8_t req[6];
        uint32_t key;

        if (argc > 1)
        {
            /* Cle imposee : sert a montrer un refus. */
            key = (uint32_t)strtoul(argv[1], NULL, 16);
        }
        else if (g_have_seed != 0)
        {
            key = uds_demo_key_from_seed(g_last_seed);
        }
        else
        {
            printf("      aucune graine connue : lancez \"seed\" d'abord\n");
            return 0;
        }

        req[0] = UDS_SID_SECURITY_ACCESS;
        req[1] = UDS_SECURITY_SEND_KEY;
        req[2] = (uint8_t)((key >> 24) & 0xFFu);
        req[3] = (uint8_t)((key >> 16) & 0xFFu);
        req[4] = (uint8_t)((key >> 8) & 0xFFu);
        req[5] = (uint8_t)(key & 0xFFu);
        send_uds(req, 6u);
        return 0;
    }

    if (strcmp(argv[0], "reset") == 0)
    {
        uint8_t req[2] = { UDS_SID_ECU_RESET, 0x01 };
        send_uds(req, 2u);
        return 0;
    }

    if (strcmp(argv[0], "present") == 0)
    {
        uint8_t req[2] = { UDS_SID_TESTER_PRESENT, 0x00 };
        send_uds(req, 2u);
        return 0;
    }

    if (strcmp(argv[0], "raw") == 0)
    {
        uint8_t payload[MAX_PAYLOAD];
        uint16_t len = 0u;
        int i;

        for (i = 1; (i < argc) && (len < MAX_PAYLOAD); i++)
        {
            payload[len++] = (uint8_t)strtoul(argv[i], NULL, 16);
        }
        if (len == 0u)
        {
            printf("      usage : raw 22 F1 90\n");
            return 0;
        }
        send_uds(payload, len);
        return 0;
    }

    printf("      commande inconnue : %s   (\"help\")\n", argv[0]);
    return 0;
}

/* ------------------------------------------------------------------ */

int main(void)
{
    char line[MAX_LINE];
    char *argv[32];

    g_interactive = isatty(STDIN_FILENO);

    if (can_socket_open(&g_sock, CAN_INTERFACE, RX_TICK_MS) != 0)
    {
        return 1;
    }

    diag_link_init(&g_link, &g_sock,
                   CAN_ID_TESTER_TO_ECU,
                   CAN_ID_ECU_TO_TESTER,
                   0);

    printf("=== Client de diagnostic ===\n");
    printf("interface %s   requetes 0x%03X   reponses 0x%03X\n",
           CAN_INTERFACE, CAN_ID_TESTER_TO_ECU, CAN_ID_ECU_TO_TESTER);
    printf("\"help\" pour la liste des commandes.\n");

    for (;;)
    {
        int argc;

        prompt();

        if (fgets(line, sizeof(line), stdin) == NULL)
        {
            printf("\n");
            break;
        }

        line[strcspn(line, "\r\n")] = '\0';

        /*
         * Entree non interactive : on reaffiche la commande, sinon un
         * enregistrement ne montrerait que les reponses.
         */
        if (g_interactive == 0)
        {
            printf("%s\n", line);
        }

        /* Ligne vide ou commentaire de scenario. */
        if ((line[0] == '\0') || (line[0] == '#'))
        {
            continue;
        }

        argc = split(line, argv, 32);

        if (execute(argc, argv) != 0)
        {
            break;
        }
    }

    printf("\n");
    can_socket_close(&g_sock);
    return 0;
}
