/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "curl_setup.h"
#if defined(USE_OPENHITLS)
#include "curl/curl.h"
#include "vtls.h"
#include "vtls_int.h"

#include "bsl_err.h"
#include "bsl_list.h"
#include "bsl_log.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "curl_printf.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"
#include "openssl.h"
#include "curl_trc.h"

#define hitls_ssl_backend_data ossl_ctx

static int hitls_init(void)
{
    int32_t ret = BSL_GLOBAL_Init();
    if (ret != BSL_SUCCESS) {
        return FALSE;
    }
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        return FALSE;
    }
    ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS && ret != CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        return FALSE;
    }
    ret = HITLS_CertMethodInit();
    if (ret != HITLS_SUCCESS) {
        return FALSE;
    }
    HITLS_CryptMethodInit();
    return TRUE;
}

static HITLS_CERT_Store *BuildCertStoreFromList(BslList *certList, struct Curl_easy *data)
{
    int32_t ret = 0;
    HITLS_CERT_Store *x509Store = NULL;
    HITLS_X509_Cert *cert = NULL;

    x509Store = HITLS_X509_StoreCtxNew();
    if (x509Store == NULL) {
        failf(data, "HITLS_X509_StoreCtxNew failed.");
        goto exit;
    }

    cert = BSL_LIST_GET_FIRST(certList);
    while (cert != NULL) {
        ret = HITLS_X509_StoreCtxCtrl(x509Store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, 0);
        if (ret != HITLS_SUCCESS) {
            failf(data, "HITLS_X509_CtrlStoreCtx failed 0x%x.", ret);
            goto exit;
        }
        cert = BSL_LIST_GET_NEXT(certList);
    }

    return x509Store;
exit:
    HITLS_X509_StoreCtxFree(x509Store);
    HITLS_X509_CertFree(cert);
    return NULL;
}

static int SetCertListToChainStore(HITLS_Config *config, BslList *certList, struct Curl_easy *data)
{
    HITLS_CERT_Store *chainStore = BuildCertStoreFromList(certList, data);
    if (chainStore == NULL) {
        failf(data, "Failed to build chain store from list.");
        goto exit;
    }

    if (HITLS_CFG_SetChainStore(config, chainStore, false) != HITLS_SUCCESS) {
        failf(data, "Failed to set chain store.");
        goto exit;
    }

    return CURLE_OK;
exit:
    HITLS_X509_StoreCtxFree(chainStore);
    return CURLE_SSL_CONNECT_ERROR;
}

static int SetCertListToCertStore(HITLS_Config *config, BslList *certList, struct Curl_easy *data)
{
    HITLS_CERT_Store *certStore = BuildCertStoreFromList(certList, data);
    if (certStore == NULL) {
        failf(data, "Failed to build cert store from list.");
        goto exit;
    }

    if (HITLS_CFG_SetCertStore(config, certStore, false) != HITLS_SUCCESS) {
        failf(data, "Failed to set cert store.");
        goto exit;
    }

    return CURLE_OK;
exit:
    HITLS_X509_StoreCtxFree(certStore);
    return CURLE_SSL_CONNECT_ERROR;
}

static int32_t ParseAndSetCACertificate(HITLS_Config *config, const char *caFile, uint32_t depth,
                                        struct Curl_easy *data)
{
    BslList *certList = NULL;
    if (caFile == NULL) {
        failf(data, "caFile is NULL.");
        return CURLE_OK;
    }

    int32_t ret = HITLS_CFG_SetVerifyDepth(config, depth);
    if (ret != HITLS_SUCCESS) {
        failf(data, "HITLS_CFG_SetVerifyDepth failed.");
        goto exit;
    }

    ret = HITLS_X509_CertParseBundleFile(BSL_FORMAT_PEM, caFile, &certList);
    if (ret != HITLS_PKI_SUCCESS) {
        failf(data, "Error parsing CA certificate.");
        goto exit;
    }

    if (certList != NULL) {
        ret = SetCertListToCertStore(config, certList, data);
        if (ret != CURLE_OK) {
            failf(data, "Set CA Certificate list to cert store failed.");
            goto exit;
        }
    }

    ret = HITLS_CFG_SetClientVerifySupport(config, true);
    if (ret != HITLS_SUCCESS) {
        failf(data, "HITLS_CFG_SetClientVerifySupport failed.");
        goto exit;
    }

    return CURLE_OK;
exit:
    BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return CURLE_SSL_CONNECT_ERROR;
}

static HITLS_X509_Cert *LoadCertListAndCert(const char *certFile, BslList **certList, const char *certName,
                                            struct Curl_easy *data)
{
    HITLS_X509_Cert *cert = NULL;
    BslListNode *detachNode = NULL;
    if (certFile == NULL) {
        failf(data, "certFile is NULL.");
        return NULL;
    }

    if (HITLS_X509_CertParseBundleFile(BSL_FORMAT_PEM, certFile, certList) != HITLS_PKI_SUCCESS) {
        failf(data, "Error parsing certificate: %s.", certName);
        goto exit;
    }

    if (*certList == NULL || BSL_LIST_COUNT(*certList) == 0) {
        failf(data, "certList is empty: %s.", certName);
        goto exit;
    }
    cert = BSL_LIST_GET_FIRST(*certList);
    if (cert == NULL) {
        failf(data, "BSL_LIST_GET_FIRST failed: %s.", certName);
        goto exit;
    }

    detachNode = BSL_LIST_FirstNode(*certList);
    BSL_LIST_DetachNode(*certList, &detachNode);
    if (BSL_LIST_COUNT(*certList) == 0) {
        BSL_LIST_FREE(*certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }

    return cert;
exit:
    BSL_LIST_FREE(*certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return NULL;
}

static CRYPT_EAL_PkeyCtx *ParseFilePriKey(const char *path, uint8_t *pwd, uint32_t pwdlen, struct Curl_easy *data)
{
    static int32_t tryTypes[] = {CRYPT_PRIKEY_PKCS8_UNENCRYPT, CRYPT_PRIKEY_PKCS8_ENCRYPT, CRYPT_PRIKEY_RSA,
                                 CRYPT_PRIKEY_ECC};
    CRYPT_EAL_PkeyCtx *ealPriKey = NULL;
    uint32_t i = 0;
    if (path == NULL) {
        failf(data, "path is NULL.");
        return NULL;
    }
    for (; i < sizeof(tryTypes) / sizeof(tryTypes[0]); i++) {
        if (CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, tryTypes[i], path, pwd, pwdlen, &ealPriKey) == HITLS_SUCCESS) {
            return ealPriKey;
        }
    }

    failf(data, "BSL_ParseFormat is incorrect.");
    CRYPT_EAL_PkeyFreeCtx(ealPriKey);
    return NULL;
}

static int32_t ParseAndSetCertificate(const char *certFile, HITLS_Config *config, bool isEncryption,
                                      const char *certName, const long int sslVersion, struct Curl_easy *data)
{
    int32_t ret = 0;
    BslList *certList = NULL;
    HITLS_X509_Cert *cert = NULL;
    if (certFile == NULL) {
        failf(data, "certFile is NULL.");
        return CURLE_OK;
    }

    cert = LoadCertListAndCert(certFile, &certList, certName, data);
    if (cert == NULL) {
        failf(data, "LoadCertListAndCert failed: %s.", certName);
        goto exit;
    }

    if (certList != NULL) {
        ret = SetCertListToChainStore(config, certList, data);
        if (ret != CURLE_OK) {
            failf(data, "Set %s list to chain store failed.", certName);
            goto exit;
        }
    }

    if (sslVersion == CURL_SSLVERSION_TLCPv1_1) { /* TLCP */
        ret = HITLS_CFG_SetTlcpCertificate(config, cert, false, isEncryption);
        if (ret != HITLS_SUCCESS) {
            failf(data, "Error adding certificate to configuration: %s.", certName);
            goto exit;
        }
    } else {
        failf(data, "This version is not supported.");
        goto exit;
    }

    return CURLE_OK;
exit:
    BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return CURLE_SSL_CONNECT_ERROR;
}

static int32_t ParseAndSetPrivateKey(const char *keyFile, HITLS_Config *config, bool isEncryption, const char *keyName,
                                     const long int sslVersion, struct Curl_easy *data)
{
    int32_t ret = 0;
    CRYPT_EAL_PkeyCtx *certKey = NULL;
    if (keyFile == NULL) {
        failf(data, "keyFile is NULL.");
        return CURLE_OK;
    }
    certKey = ParseFilePriKey(keyFile, NULL, 0, data);
    if (certKey == NULL) {
        failf(data, "Error parsing private key: %s.", keyName);
        goto exit;
    }
    if (sslVersion == CURL_SSLVERSION_TLCPv1_1) { /* TLCP */
        ret = HITLS_CFG_SetTlcpPrivateKey(config, (HITLS_CERT_Key *)certKey, false, isEncryption);
        if (ret != HITLS_SUCCESS) {
            failf(data, "Error adding private key to configuration: %s.", keyName);
            if (ret == HITLS_CERT_ERR_CHECK_CERT_AND_KEY) {
                failf(data, "TLCP Certificate and Key check failed.");
            } else {
                failf(data, "HITLS_CFG_SetPrivateKey failed 0x%x.", ret);
            }
            goto exit;
        }
    } else {
        failf(data, "This version is not supported.");
        goto exit;
    }
    return CURLE_OK;
exit:
    CRYPT_EAL_PkeyFreeCtx(certKey);
    return CURLE_SSL_CONNECT_ERROR;
}

static CURLcode hitls_connect_nonblocking_step1(struct hitls_ssl_backend_data *backend, struct Curl_cfilter *cf,
    struct Curl_easy *data)
{
    int32_t ret = 0;
    struct ssl_config_data *sslConfig = Curl_ssl_cf_get_config(cf, data);
    const long int sslVersion = sslConfig->primary.version;
    if (sslVersion != CURL_SSLVERSION_TLCPv1_1) {
        failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION in hitls.");
        return CURLE_NOT_BUILT_IN;
    }
    if (backend && backend->ctx == NULL) {
        backend->config = HITLS_CFG_NewTLCPConfig();
        if (backend->config == NULL) {
            failf(data, "HITLS_CFG_NewTLCPConfig failed.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        uint16_t cipherSuite = HITLS_ECC_SM4_CBC_SM3;
        if (HITLS_CFG_SetCipherSuites(backend->config, &cipherSuite, 1) != HITLS_SUCCESS) {
            failf(data, "HITLS_CFG_SetCipherSuites error.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = HITLS_CFG_SetCheckKeyUsage(backend->config, false);
        if (ret != HITLS_SUCCESS) {
            failf(data, "HITLS_SetCheckKeyUsage failed.");
            return CURLE_SSL_CONNECT_ERROR;
        }
    } else {
        return CURLE_SSL_CONNECT_ERROR;
    }
    return CURLE_OK;
}

static CURLcode hitls_connect_nonblocking_step2(struct hitls_ssl_backend_data *backend, struct Curl_cfilter *cf,
    struct Curl_easy *data)
{
    int32_t ret = 0;
    struct ssl_config_data *sslConfig = Curl_ssl_cf_get_config(cf, data);
    char *const sslCafile = sslConfig->primary.CAfile;
    char *const sslSignCert = sslConfig->primary.clientcert;
    char *const sslEncCert = sslConfig->primary.clientcertEnc;
    char *const sslSignKey = sslConfig->key;
    char *const sslEncKey = sslConfig->encKey;
    const long int sslVersion = sslConfig->primary.version;
    uint32_t depth = 20;
    if (backend && backend->config != NULL) {
        ret = ParseAndSetCACertificate(backend->config, sslCafile, depth, data);
        if (ret != CURLE_OK) {
            failf(data, "Some problems were encountered when processing CA Certificate.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = ParseAndSetCertificate(sslSignCert, backend->config, false, "Signing Certificate", sslVersion, data);
        if (ret != CURLE_OK) {
            failf(data, "Some problems were encountered when processing Signing Certificate.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = ParseAndSetPrivateKey(sslSignKey, backend->config, false, "Signing Private Key", sslVersion, data);
        if (ret != CURLE_OK) {
            failf(data, "Some problems were encountered when processing Signing Private Key.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = ParseAndSetCertificate(sslEncCert, backend->config, true, "Encryption Certificate", sslVersion, data);
        if (ret != CURLE_OK) {
            failf(data, "Some problems were encountered when processing Encryption Certificate.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = ParseAndSetPrivateKey(sslEncKey, backend->config, true, "Encryption Private Key", sslVersion, data);
        if (ret != CURLE_OK) {
            failf(data, "Some problems were encountered when processing Encryption Private Key.");
            return CURLE_SSL_CONNECT_ERROR;
        }
    } else {
        return CURLE_SSL_CONNECT_ERROR;
    }
    return CURLE_OK;
}

static CURLcode hitls_connect_nonblocking_step3(struct hitls_ssl_backend_data *backend, struct Curl_cfilter *cf,
    struct Curl_easy *data)
{
    int32_t ret = 0;
    BSL_UIO *uio = NULL;
    curl_socket_t sockfd;
    if (backend && backend->config != NULL) {
        backend->ctx = HITLS_New(backend->config);
        if (backend->ctx == NULL) {
            failf(data, "HITLS_New failed.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        sockfd = Curl_conn_cf_get_socket(cf, data);
        if (sockfd < 0) {
            failf(data, "TCP_Connect failed.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        uio = BSL_UIO_New(BSL_UIO_TcpMethod());
        if (uio == NULL) {
            failf(data, "BSL_UIO_New failed.");
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(sockfd), &sockfd);
        if (ret != HITLS_SUCCESS) {
            BSL_UIO_Free(uio);
            failf(data, "BSL_UIO_SET_FD failed, sockfd = %u.", sockfd);
            return CURLE_SSL_CONNECT_ERROR;
        }
        ret = HITLS_SetUio(backend->ctx, uio);
        if (ret != HITLS_SUCCESS) {
            BSL_UIO_Free(uio);
            failf(data, "HITLS_SetUio failed. ret = 0x%x.", ret);
            return CURLE_SSL_CONNECT_ERROR;
        }
    } else {
        return CURLE_SSL_CONNECT_ERROR;
    }
    return CURLE_OK;
}

static CURLcode hitls_connect_nonblocking(struct Curl_cfilter *cf, struct Curl_easy *data, bool *done)
{
    int32_t ret = 0;
    struct ssl_connect_data *connssl = cf->ctx;
    struct hitls_ssl_backend_data *backend = (struct hitls_ssl_backend_data *)connssl->backend;
    if (hitls_connect_nonblocking_step1(backend, cf, data) != CURLE_OK) {
        goto exit;
    }
    if (hitls_connect_nonblocking_step2(backend, cf, data) != CURLE_OK) {
        goto exit;
    }
    if (hitls_connect_nonblocking_step3(backend, cf, data) != CURLE_OK) {
        goto exit;
    }
    do {
        ret = HITLS_Connect(backend->ctx);
    } while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    if (ret != HITLS_SUCCESS) {
        failf(data, "HITLS_Connect failed.");
        goto exit;
    }
    if (done != NULL) {
        *done = TRUE;
    }
    return CURLE_OK;
exit:
    if (backend->ctx != NULL) {
        HITLS_Close(backend->ctx);
        HITLS_Free(backend->ctx);
        backend->ctx = NULL;
    }
    if (backend->config != NULL) {
        HITLS_CFG_FreeConfig(backend->config);
        backend->config = NULL;
    }
    return CURLE_SSL_CONNECT_ERROR;
}

static ssize_t hitls_recv(struct Curl_cfilter *cf, struct Curl_easy *data, char *buf, size_t bufferSize,
                          CURLcode *curlCode)
{
    int ret = 0;
    unsigned int readLen = 0;

    struct ssl_connect_data *connssl = cf->ctx;
    struct hitls_ssl_backend_data *backend = (struct hitls_ssl_backend_data *)connssl->backend;

    ret = HITLS_Read(backend->ctx, buf, bufferSize, &readLen);
    if (ret == HITLS_SUCCESS) {
        buf[readLen] = '\0'; // Ensure null-termination
        return readLen;
    } else if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
        *curlCode = CURLE_AGAIN;
    } else {
        *curlCode = CURLE_RECV_ERROR;
    }

    return -1;
}

static ssize_t hitls_send(struct Curl_cfilter *cf, struct Curl_easy *data, const void *mem, size_t len,
                          CURLcode *curlCode)
{
    int ret = 0;
    uint32_t writeLen = 0;
    struct ssl_connect_data *connssl = cf->ctx;
    struct hitls_ssl_backend_data *backend = (struct hitls_ssl_backend_data *)connssl->backend;

    ret = HITLS_Write(backend->ctx, mem, len, &writeLen);
    if (ret == HITLS_SUCCESS) {
        return writeLen;
    } else if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
        *curlCode = CURLE_AGAIN;
    } else {
        *curlCode = CURLE_RECV_ERROR;
    }

    return -1;
}

static CURLcode hitls_connect(struct Curl_cfilter *cf, struct Curl_easy *data)
{
    return CURLE_NOT_BUILT_IN;
}

static size_t hitls_version(char *buffer, size_t size)
{
    return msnprintf(buffer, size, "TLCP1.1");
}

static void *hitls_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
    return NULL;
}

static void hitls_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
    struct ssl_connect_data *connssl = cf->ctx;
    struct hitls_ssl_backend_data *backend = (struct hitls_ssl_backend_data *)connssl->backend;

    if (backend != NULL) {
        HITLS_Close(backend->ctx);
        HITLS_Free(backend->ctx);
        backend->ctx = NULL;
        HITLS_CFG_FreeConfig(backend->config);
        backend->config = NULL;
    }
}

const struct Curl_ssl Curl_ssl_hitls = {
    {CURLSSLBACKEND_OPENHITLS, "hitls"},
    0,
    sizeof(struct hitls_ssl_backend_data),

    hitls_init,                    /* init */
    Curl_none_cleanup,             /* cleanup */
    hitls_version,                 /* version */
    Curl_none_check_cxn,           /* check_cxn */
    Curl_none_shutdown,            /* shutdown */
    Curl_none_data_pending,        /* data_pending */
    Curl_none_random,              /* random */
    Curl_none_cert_status_request, /* cert_status_request */
    hitls_connect,                 /* connect */
    hitls_connect_nonblocking,     /* connect_nonblocking */
    Curl_ssl_adjust_pollset,       /* adjust_pollset */
    hitls_get_internals,           /* get_internals */
    hitls_close,                   /* close_one */
    Curl_none_close_all,           /* close_all */
    Curl_none_set_engine,          /* set_engine */
    Curl_none_set_engine_default,  /* set_engine_default */
    Curl_none_engines_list,        /* engines_list */
    Curl_none_false_start,         /* false_start */
    NULL,                          /* sha256sum */
    NULL,                          /* use of data in this connection */
    NULL,                          /* remote of data from this connection */
    NULL,
    hitls_recv, /* recv decrypted data */
    hitls_send, /* send data to encrypt */
};

#endif /* USE_OPENHITLS */