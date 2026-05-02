/*-
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This demonstration generates and verifies an SLH-DSA-SHA2-128s signature
 * (FIPS 205) using the streaming EVP_PKEY_sign_message_* and
 * EVP_PKEY_verify_message_* APIs.
 *
 * SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is a
 * post-quantum signature scheme standardised as FIPS 205.  It uses only
 * hash functions so its security proofs rely solely on the security of
 * those hash functions.  Twelve parameter sets are available, named
 * SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/* Algorithm name – change to any of the 12 SLH-DSA parameter sets. */
#define SLH_DSA_ALG "SLH-DSA-SHA2-128s"

/* A test message to be signed. */
static const unsigned char message[] =
    "Thou art more lovely and more temperate.\n"
    "Rough winds do shake the darling buds of May,\n"
    "And summer's lease hath all too short a date.\n";

/*
 * Generate an SLH-DSA key pair.
 * The public key is extracted from the private key object.
 */
static int create_key(OSSL_LIB_CTX *libctx,
                      EVP_PKEY **privout, EVP_PKEY **pubout)
{
    int ret = 0;
    EVP_PKEY *priv = NULL, *pub = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char pubdata[64]; /* largest SLH-DSA public key is 64 bytes */
    size_t pubdata_len = 0;

    priv = EVP_PKEY_Q_keygen(libctx, NULL, SLH_DSA_ALG);
    if (priv == NULL) {
        fprintf(stderr, "EVP_PKEY_Q_keygen() for %s failed\n", SLH_DSA_ALG);
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
    pctx = EVP_PKEY_CTX_new_from_name(libctx, SLH_DSA_ALG, NULL);
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
 * Sign a message with the SLH-DSA private key.
 *
 * Note: SLH-DSA-SHA2-128s produces 7856-byte signatures.
 *       The slower 's' variants trade signing speed for smaller signatures.
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

    if (EVP_PKEY_sign_message_init(sctx, NULL, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_init() failed\n");
        goto cleanup;
    }
    if (EVP_PKEY_sign_message_update(sctx, message, sizeof(message)) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_update() failed\n");
        goto cleanup;
    }
    /* Query the required signature buffer size. */
    if (EVP_PKEY_sign_message_final(sctx, NULL, &siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_final() (size query) failed\n");
        goto cleanup;
    }
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "OPENSSL_malloc() failed\n");
        goto cleanup;
    }

    /* Re-initialise and replay the update to actually produce the signature. */
    if (EVP_PKEY_sign_message_init(sctx, NULL, NULL) <= 0
            || EVP_PKEY_sign_message_update(sctx, message,
                                            sizeof(message)) <= 0) {
        fprintf(stderr, "Re-initialisation for signing failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating %s signature (%zu bytes) — "
            "this may take a moment...\n", SLH_DSA_ALG, siglen);
    if (EVP_PKEY_sign_message_final(sctx, sig, &siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_final() failed\n");
        goto cleanup;
    }
    /* Print only the first 64 bytes of the (large) signature for brevity. */
    fprintf(stdout, "Signature (first 64 bytes of %zu):\n", siglen);
    BIO_dump_indent_fp(stdout, sig, 64, 2);
    fprintf(stdout, "  ...\n\n");

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
 * Verify the signature using the SLH-DSA public key.
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
    if (EVP_PKEY_verify_message_update(vctx, message, sizeof(message)) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_update() failed\n");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_signature(vctx, sig, siglen) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_signature() failed\n");
        goto cleanup;
    }
    if (EVP_PKEY_verify_message_final(vctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_final() failed\n");
        goto cleanup;
    }
    fprintf(stdout, "%s signature verified successfully.\n", SLH_DSA_ALG);
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
        fprintf(stderr, "Failed to create %s key pair\n", SLH_DSA_ALG);
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
