/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a demonstration of key encapsulation using ML-KEM-768 (FIPS 203),
 * a post-quantum Key Encapsulation Mechanism (KEM).
 *
 * In a KEM, two parties – the sender and the recipient – agree on a shared
 * secret as follows:
 *
 *   1. The recipient generates a key pair and sends the public key to the
 *      sender.
 *   2. The sender calls EVP_PKEY_encapsulate() with the recipient's public
 *      key.  This produces:
 *        - a ciphertext that is sent to the recipient, and
 *        - a shared secret that only the sender knows at this point.
 *   3. The recipient calls EVP_PKEY_decapsulate() with their private key and
 *      the ciphertext received from the sender.  This recovers the same
 *      shared secret.
 *
 * Both parties now hold the same shared secret, which can be used as key
 * material for symmetric encryption (e.g. by passing it through HKDF).
 *
 * Three ML-KEM variants are available: ML-KEM-512, ML-KEM-768 and
 * ML-KEM-1024, offering increasing security levels and key/ciphertext sizes.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

/* Object used to store information for one party */
typedef struct party_data_st {
    const char *name;
    EVP_PKEY *priv;   /* private key (recipient only) */
    EVP_PKEY *pub;    /* public key  (shared with sender) */
    unsigned char *secret;
    size_t secretlen;
} PARTY_DATA;

static void destroy_party(PARTY_DATA *p)
{
    EVP_PKEY_free(p->priv);
    EVP_PKEY_free(p->pub);
    OPENSSL_free(p->secret);
    p->priv   = NULL;
    p->pub    = NULL;
    p->secret = NULL;
}

/*
 * Generate an ML-KEM-768 key pair for the recipient.
 * The public key is extracted and stored separately for the sender's use.
 */
static int create_recipient_key(PARTY_DATA *recipient, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char pubdata[1184]; /* ML-KEM-768 public key is 1184 bytes */
    size_t pubdata_len = 0;

    recipient->priv = EVP_PKEY_Q_keygen(libctx, NULL, "ML-KEM-768");
    if (recipient->priv == NULL) {
        fprintf(stderr, "EVP_PKEY_Q_keygen() for ML-KEM-768 failed\n");
        goto err;
    }

    /* Extract the raw public key bytes */
    if (!EVP_PKEY_get_octet_string_param(recipient->priv, OSSL_PKEY_PARAM_PUB_KEY,
                                          pubdata, sizeof(pubdata),
                                          &pubdata_len)) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param(pub) failed\n");
        goto err;
    }

    /* Build a public-key-only EVP_PKEY to hand to the sender */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, "ML-KEM-768", NULL);
    if (pctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto err;
    }
    {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                       pubdata, pubdata_len);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(pctx) <= 0
                || EVP_PKEY_fromdata(pctx, &recipient->pub,
                                     EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            fprintf(stderr, "EVP_PKEY_fromdata() for public key failed\n");
            goto err;
        }
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
 * Sender encapsulates: uses the recipient's public key to produce a
 * ciphertext and a shared secret.
 *
 * The ciphertext must be sent to the recipient (in a real application, over
 * an authenticated channel).
 */
static int sender_encapsulate(PARTY_DATA *sender,
                               EVP_PKEY *recipient_pub,
                               OSSL_LIB_CTX *libctx,
                               unsigned char **ct_out, size_t *ct_out_len)
{
    int ret = 0;
    EVP_PKEY_CTX *ectx = NULL;
    unsigned char *ct = NULL;
    size_t ctlen = 0, secretlen = 0;

    ectx = EVP_PKEY_CTX_new_from_pkey(libctx, recipient_pub, NULL);
    if (ectx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate_init() failed\n");
        goto cleanup;
    }

    /* Query required buffer sizes */
    if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &secretlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate() (size query) failed\n");
        goto cleanup;
    }

    ct = OPENSSL_malloc(ctlen);
    sender->secret = OPENSSL_malloc(secretlen);
    if (ct == NULL || sender->secret == NULL) {
        fprintf(stderr, "OPENSSL_malloc() failed\n");
        goto cleanup;
    }

    /* Perform the actual encapsulation */
    if (EVP_PKEY_encapsulate(ectx, ct, &ctlen,
                              sender->secret, &secretlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate() failed\n");
        goto cleanup;
    }
    sender->secretlen = secretlen;

    fprintf(stdout, "Sender (%s) shared secret:\n", sender->name);
    BIO_dump_indent_fp(stdout, sender->secret, (int)sender->secretlen, 2);
    fprintf(stdout, "\n");

    *ct_out     = ct;
    *ct_out_len = ctlen;
    ret = 1;

cleanup:
    if (!ret) {
        OPENSSL_free(ct);
        OPENSSL_free(sender->secret);
        sender->secret    = NULL;
        sender->secretlen = 0;
    }
    EVP_PKEY_CTX_free(ectx);
    return ret;
}

/*
 * Recipient decapsulates: uses their private key and the received ciphertext
 * to recover the shared secret.
 */
static int recipient_decapsulate(PARTY_DATA *recipient,
                                  OSSL_LIB_CTX *libctx,
                                  const unsigned char *ct, size_t ctlen)
{
    int ret = 0;
    EVP_PKEY_CTX *dctx = NULL;
    size_t secretlen = 0;

    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, recipient->priv, NULL);
    if (dctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate_init() failed\n");
        goto cleanup;
    }

    /* Query required buffer size for the secret */
    if (EVP_PKEY_decapsulate(dctx, NULL, &secretlen, ct, ctlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate() (size query) failed\n");
        goto cleanup;
    }

    recipient->secret = OPENSSL_malloc(secretlen);
    if (recipient->secret == NULL) {
        fprintf(stderr, "OPENSSL_malloc() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate(dctx, recipient->secret, &secretlen,
                              ct, ctlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate() failed\n");
        goto cleanup;
    }
    recipient->secretlen = secretlen;

    fprintf(stdout, "Recipient (%s) shared secret:\n", recipient->name);
    BIO_dump_indent_fp(stdout, recipient->secret,
                       (int)recipient->secretlen, 2);
    fprintf(stdout, "\n");
    ret = 1;

cleanup:
    if (!ret) {
        OPENSSL_free(recipient->secret);
        recipient->secret    = NULL;
        recipient->secretlen = 0;
    }
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

int main(void)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *libctx = NULL;
    PARTY_DATA sender    = { "sender"    };
    PARTY_DATA recipient = { "recipient" };
    unsigned char *ciphertext = NULL;
    size_t ciphertextlen = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }

    /* Step 1: recipient generates a key pair. */
    if (!create_recipient_key(&recipient, libctx)) {
        fprintf(stderr, "Failed to create recipient key pair\n");
        goto cleanup;
    }

    /*
     * Step 2: sender encapsulates using the recipient's public key,
     *         producing a ciphertext and a local shared secret.
     */
    if (!sender_encapsulate(&sender, recipient.pub, libctx,
                             &ciphertext, &ciphertextlen)) {
        fprintf(stderr, "Sender encapsulation failed\n");
        goto cleanup;
    }

    /*
     * Step 3: recipient decapsulates using their private key and the
     *         ciphertext, recovering the shared secret.
     */
    if (!recipient_decapsulate(&recipient, libctx, ciphertext, ciphertextlen)) {
        fprintf(stderr, "Recipient decapsulation failed\n");
        goto cleanup;
    }

    /* Verify that both parties derived the same secret. */
    if (sender.secretlen != recipient.secretlen
            || CRYPTO_memcmp(sender.secret, recipient.secret,
                             sender.secretlen) != 0) {
        fprintf(stderr, "Shared secrets do NOT match!\n");
        goto cleanup;
    }
    fprintf(stdout, "ML-KEM-768: shared secrets match.\n");

    ret = EXIT_SUCCESS;

cleanup:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    OPENSSL_free(ciphertext);
    destroy_party(&sender);
    destroy_party(&recipient);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
