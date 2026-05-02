/*-
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This demonstration generates and verifies an ML-DSA-65 signature
 * (FIPS 204) using the streaming EVP_PKEY_sign_message_* and
 * EVP_PKEY_verify_message_* APIs.
 *
 * ML-DSA (Module Lattice Digital Signature Algorithm) is a post-quantum
 * signature scheme standardised as FIPS 204.  Three parameter sets are
 * available: ML-DSA-44, ML-DSA-65 and ML-DSA-87.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/* A test message to be signed, split into two parts to show streaming. */
static const unsigned char msg_part1[] =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n";
static const unsigned char msg_part2[] =
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles.\n";

/*
 * Generate an ML-DSA-65 private/public key pair.
 * The public key is extracted from the private key object.
 */
static int create_key(OSSL_LIB_CTX *libctx,
                      EVP_PKEY **privout, EVP_PKEY **pubout)
{
    int ret = 0;
    EVP_PKEY *priv = NULL, *pub = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char pubdata[1952]; /* ML-DSA-65 public key is 1952 bytes */
    size_t pubdata_len = 0;

    priv = EVP_PKEY_Q_keygen(libctx, NULL, "ML-DSA-65");
    if (priv == NULL) {
        fprintf(stderr, "EVP_PKEY_Q_keygen() for ML-DSA-65 failed\n");
        goto end;
    }

    /* Extract the public key bytes from the private key object */
    if (!EVP_PKEY_get_octet_string_param(priv, OSSL_PKEY_PARAM_PUB_KEY,
                                          pubdata, sizeof(pubdata),
                                          &pubdata_len)) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param(pub) failed\n");
        goto end;
    }

    /* Build a public-key-only EVP_PKEY from the raw bytes */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, "ML-DSA-65", NULL);
    if (pctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto end;
    }
    {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                       pubdata, pubdata_len);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(pctx) <= 0
                || EVP_PKEY_fromdata(pctx, &pub,
                                     EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            fprintf(stderr, "EVP_PKEY_fromdata() for public key failed\n");
            goto end;
        }
    }
    ret = 1;
end:
    EVP_PKEY_CTX_free(pctx);
    if (ret) {
        *privout = priv;
        *pubout  = pub;
    } else {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
    }
    return ret;
}

/*
 * Sign a two-part message with an ML-DSA-65 private key using the
 * streaming sign_message API.
 */
static int demo_sign(EVP_PKEY *priv,
                     OSSL_LIB_CTX *libctx,
                     unsigned char **sig_out,
                     size_t *sig_out_len)
{
    int ret = 0;
    EVP_PKEY_CTX *sctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    sctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv, NULL);
    if (sctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto cleanup;
    }

    /*
     * Initialise for signing.  Pass NULL for the EVP_SIGNATURE object so
     * the default algorithm associated with the key type is used.
     */
    if (EVP_PKEY_sign_message_init(sctx, NULL, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_init() failed\n");
        goto cleanup;
    }

    /* Feed the message in two parts to demonstrate the streaming API. */
    if (EVP_PKEY_sign_message_update(sctx, msg_part1, sizeof(msg_part1)) <= 0
            || EVP_PKEY_sign_message_update(sctx, msg_part2,
                                            sizeof(msg_part2)) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_update() failed\n");
        goto cleanup;
    }

    /* Determine the required signature length. */
    if (EVP_PKEY_sign_message_final(sctx, NULL, &siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_final() (size query) failed\n");
        goto cleanup;
    }
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "OPENSSL_malloc() failed\n");
        goto cleanup;
    }

    /*
     * The streaming sign API does not support re-initialisation after a
     * final call, so we re-initialise and replay the update steps.
     */
    if (EVP_PKEY_sign_message_init(sctx, NULL, NULL) <= 0
            || EVP_PKEY_sign_message_update(sctx, msg_part1,
                                            sizeof(msg_part1)) <= 0
            || EVP_PKEY_sign_message_update(sctx, msg_part2,
                                            sizeof(msg_part2)) <= 0) {
        fprintf(stderr, "Re-initialisation for signing failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating ML-DSA-65 signature (%zu bytes):\n", siglen);
    if (EVP_PKEY_sign_message_final(sctx, sig, &siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_final() failed\n");
        goto cleanup;
    }
    BIO_dump_indent_fp(stdout, sig, (int)siglen, 2);
    fprintf(stdout, "\n");

    *sig_out     = sig;
    *sig_out_len = siglen;
    ret = 1;

cleanup:
    if (!ret)
        OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    return ret;
}

/*
 * Verify the signature against the same two-part message using an
 * ML-DSA-65 public key.
 */
static int demo_verify(EVP_PKEY *pub,
                       OSSL_LIB_CTX *libctx,
                       const unsigned char *sig, size_t siglen)
{
    int ret = 0;
    EVP_PKEY_CTX *vctx = NULL;

    vctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, NULL);
    if (vctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_verify_message_init(vctx, NULL, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_init() failed\n");
        goto cleanup;
    }

    /* Feed the message in the same two parts used during signing. */
    if (EVP_PKEY_verify_message_update(vctx, msg_part1,
                                       sizeof(msg_part1)) <= 0
            || EVP_PKEY_verify_message_update(vctx, msg_part2,
                                              sizeof(msg_part2)) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_update() failed\n");
        goto cleanup;
    }

    /* Supply the signature to verify. */
    if (EVP_PKEY_CTX_set_signature(vctx, sig, siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_signature() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_verify_message_final(vctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_final() failed\n");
        goto cleanup;
    }
    fprintf(stdout, "ML-DSA-65 signature verified successfully.\n");
    ret = 1;

cleanup:
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

int main(void)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *priv = NULL, *pub = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }

    if (!create_key(libctx, &priv, &pub)) {
        fprintf(stderr, "Failed to create ML-DSA-65 key pair\n");
        goto cleanup;
    }

    if (!demo_sign(priv, libctx, &sig, &sig_len)) {
        fprintf(stderr, "demo_sign() failed\n");
        goto cleanup;
    }

    if (!demo_verify(pub, libctx, sig, sig_len)) {
        fprintf(stderr, "demo_verify() failed\n");
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

cleanup:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    OPENSSL_free(sig);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
