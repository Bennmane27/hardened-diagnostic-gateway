/*
 * test_isotp.c
 *
 * Tests unitaires de la couche ISO-TP Single Frame.
 *
 * Aucun framework externe : un compteur, une fonction check(), un code
 * de retour. Suffisant a ce stade et sans dependance a installer.
 *
 * Principe de validation le plus important de ce fichier :
 *
 *   le decodeur recoit un tampon alloue a la taille EXACTE du DLC
 *   annonce par la trame.
 *
 * Sous AddressSanitizer, toute lecture d'un octet situe au-dela de ce
 * que la trame contient reellement provoque un arret immediat. C'est
 * ce qui transforme "je pense que le parser ne deborde pas" en une
 * verification mecanique. Le bug classique d'un parser ISO-TP est
 * justement de faire confiance a la longueur annoncee dans le PCI.
 *
 * Build :
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "isotp.h"

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
 * Implementation de reference du classement d'une Single Frame,
 * ecrite depuis la specification et volontairement independante de
 * isotp.c. On compare ensuite les deux.
 *
 * Ecrire l'oracle separement evite le piege du test qui reproduit le
 * bug du code teste parce qu'il a ete derive de ce code.
 */
static isotp_result_t expected_decode(uint8_t pci, uint8_t frame_len)
{
    uint8_t type;
    uint8_t sf_dl;

    if (frame_len < 1u)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    type = (uint8_t)(pci >> 4);
    if (type != 0u)
    {
        return ISOTP_ERR_NOT_SINGLE_FRAME;
    }

    sf_dl = (uint8_t)(pci & 0x0Fu);
    if ((sf_dl == 0u) || (sf_dl > 7u))
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    if ((uint8_t)(1u + sf_dl) > frame_len)
    {
        return ISOTP_ERR_TRUNCATED_FRAME;
    }

    return ISOTP_OK;
}

/* ------------------------------------------------------------------ */
/* 1. Balayage exhaustif du decodeur                                   */
/*                                                                     */
/*    256 valeurs possibles du premier octet x 9 longueurs de trame.   */
/*    Couvre les cas demandes : DLC incoherent, type non-SF,           */
/*    longueur nulle, longueur trop grande.                            */
/* ------------------------------------------------------------------ */
static void test_decode_exhaustive(void)
{
    int pci_value;
    uint8_t frame_len;

    printf("[1] Balayage exhaustif : 256 PCI x 9 DLC = 2304 combinaisons\n");

    for (pci_value = 0; pci_value <= 255; pci_value++)
    {
        for (frame_len = 0u; frame_len <= 8u; frame_len++)
        {
            /* Taille exacte : ASAN surveille tout depassement. */
            uint8_t *frame = (uint8_t *)malloc(frame_len ? frame_len : 1u);
            const uint8_t *payload = NULL;
            uint8_t payload_len = 0u;
            isotp_result_t got;
            isotp_result_t want;
            uint8_t i;

            for (i = 0u; i < frame_len; i++)
            {
                frame[i] = (uint8_t)(0xA0u + i);
            }
            if (frame_len > 0u)
            {
                frame[0] = (uint8_t)pci_value;
            }

            got = isotp_decode_single_frame(frame, frame_len,
                                            &payload, &payload_len);
            want = expected_decode((uint8_t)pci_value, frame_len);

            g_checks++;
            if (got != want)
            {
                g_failures++;
                printf("  ECHEC : PCI=0x%02X len=%u -> %d, attendu %d\n",
                       pci_value, frame_len, (int)got, (int)want);
            }

            if (got == ISOTP_OK)
            {
                check(payload == &frame[1],
                      "la payload commence juste apres le PCI");
                check(payload_len == (uint8_t)(pci_value & 0x0F),
                      "payload_len == SF_DL");

                /* Lecture effective de chaque octet annonce : doit
                   rester dans les limites du tampon. */
                for (i = 0u; i < payload_len; i++)
                {
                    volatile uint8_t b = payload[i];
                    (void)b;
                }
            }

            free(frame);
        }
    }
    printf("    -> aucune lecture hors limites signalee par ASAN\n");
}

/* ------------------------------------------------------------------ */
/* 2. Pointeurs NULL                                                   */
/* ------------------------------------------------------------------ */
static void test_null_pointers(void)
{
    uint8_t frame[8] = { 0x02, 0x10, 0x03, 0, 0, 0, 0, 0 };
    uint8_t payload_src[2] = { 0x10, 0x03 };
    const uint8_t *payload = NULL;
    uint8_t len = 0u;
    isotp_frame_type_t type;

    printf("[2] Rejet des pointeurs NULL\n");

    check(isotp_decode_single_frame(NULL, 8, &payload, &len)
          == ISOTP_ERR_NULL_POINTER, "decode : frame NULL");
    check(isotp_decode_single_frame(frame, 8, NULL, &len)
          == ISOTP_ERR_NULL_POINTER, "decode : out_payload NULL");
    check(isotp_decode_single_frame(frame, 8, &payload, NULL)
          == ISOTP_ERR_NULL_POINTER, "decode : out_payload_len NULL");

    check(isotp_encode_single_frame(NULL, 2, frame, 8, &len)
          == ISOTP_ERR_NULL_POINTER, "encode : payload NULL");
    check(isotp_encode_single_frame(payload_src, 2, NULL, 8, &len)
          == ISOTP_ERR_NULL_POINTER, "encode : frame NULL");
    check(isotp_encode_single_frame(payload_src, 2, frame, 8, NULL)
          == ISOTP_ERR_NULL_POINTER, "encode : out_frame_len NULL");

    check(isotp_get_frame_type(NULL, 8, &type)
          == ISOTP_ERR_NULL_POINTER, "get_frame_type : frame NULL");
    check(isotp_get_frame_type(frame, 8, NULL)
          == ISOTP_ERR_NULL_POINTER, "get_frame_type : out_type NULL");
    check(isotp_get_frame_type(frame, 0, &type)
          == ISOTP_ERR_INVALID_LENGTH, "get_frame_type : trame vide");
}

/* ------------------------------------------------------------------ */
/* 3. Encodage : longueurs valides, limites et capacite                */
/* ------------------------------------------------------------------ */
static void test_encode(void)
{
    uint8_t payload[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    uint8_t frame[8];
    uint8_t out_len;
    uint8_t n;
    uint8_t i;

    printf("[3] Encodage\n");

    check(isotp_encode_single_frame(payload, 0, frame, 8, &out_len)
          == ISOTP_ERR_INVALID_LENGTH, "payload de 0 octet refuse");
    check(isotp_encode_single_frame(payload, 8, frame, 8, &out_len)
          == ISOTP_ERR_INVALID_LENGTH, "payload de 8 octets refuse (> SF max)");
    check(isotp_encode_single_frame(payload, 255, frame, 8, &out_len)
          == ISOTP_ERR_INVALID_LENGTH, "payload de 255 octets refuse");
    check(isotp_encode_single_frame(payload, 2, frame, 7, &out_len)
          == ISOTP_ERR_BUFFER_TOO_SMALL, "capacite de 7 refusee");
    check(isotp_encode_single_frame(payload, 2, frame, 0, &out_len)
          == ISOTP_ERR_BUFFER_TOO_SMALL, "capacite de 0 refusee");

    for (n = 1u; n <= 7u; n++)
    {
        memset(frame, 0xFF, sizeof(frame));

        check(isotp_encode_single_frame(payload, n, frame, 8, &out_len)
              == ISOTP_OK, "payload de 1 a 7 octets accepte");
        check(out_len == 8u, "trame emise toujours longue de 8 octets");
        check(frame[0] == n, "PCI == SF_DL (le type SF vaut 0)");

        for (i = 0u; i < n; i++)
        {
            check(frame[1 + i] == payload[i], "payload recopiee fidelement");
        }
        for (i = (uint8_t)(1u + n); i < 8u; i++)
        {
            check(frame[i] == ISOTP_PADDING_BYTE, "bourrage applique");
        }
    }
}

/* ------------------------------------------------------------------ */
/* 4. Aller-retour encode -> decode                                    */
/* ------------------------------------------------------------------ */
static void test_roundtrip(void)
{
    uint8_t src[7] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };
    uint8_t n;

    printf("[4] Aller-retour encode -> decode\n");

    for (n = 1u; n <= 7u; n++)
    {
        uint8_t frame[8];
        uint8_t out_len = 0u;
        const uint8_t *payload = NULL;
        uint8_t payload_len = 0u;

        check(isotp_encode_single_frame(src, n, frame, 8, &out_len)
              == ISOTP_OK, "encodage accepte");
        check(isotp_decode_single_frame(frame, out_len,
                                        &payload, &payload_len)
              == ISOTP_OK, "decodage accepte");
        check(payload_len == n, "longueur preservee");
        check(memcmp(payload, src, n) == 0, "contenu preserve");
    }
}

/* ------------------------------------------------------------------ */
/* 5. Classement du type de trame                                      */
/* ------------------------------------------------------------------ */
static void test_frame_type(void)
{
    struct
    {
        uint8_t pci;
        isotp_frame_type_t want;
        const char *name;
    } cases[] = {
        { 0x02, ISOTP_FRAME_SINGLE,       "Single Frame"      },
        { 0x10, ISOTP_FRAME_FIRST,        "First Frame"       },
        { 0x21, ISOTP_FRAME_CONSECUTIVE,  "Consecutive Frame" },
        { 0x30, ISOTP_FRAME_FLOW_CONTROL, "Flow Control"      },
    };
    size_t i;

    printf("[5] Classement du type de trame\n");

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        uint8_t frame[8] = { 0 };
        isotp_frame_type_t got;

        frame[0] = cases[i].pci;
        check(isotp_get_frame_type(frame, 8, &got) == ISOTP_OK,
              "appel accepte");
        check(got == cases[i].want, cases[i].name);
    }
}

int main(void)
{
    printf("=============================================\n");
    printf(" Tests unitaires ISO-TP Single Frame\n");
    printf("=============================================\n\n");

    test_decode_exhaustive();
    test_null_pointers();
    test_encode();
    test_roundtrip();
    test_frame_type();

    printf("\n=============================================\n");
    printf(" %d verifications, %d echec(s)\n", g_checks, g_failures);
    printf("=============================================\n");

    return (g_failures == 0) ? 0 : 1;
}
