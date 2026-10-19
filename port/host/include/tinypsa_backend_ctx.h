/* Context sizes for tinycred's host port, in bytes: what port/host/hash_host.c and the
 * carried primitive double need. tinypsa's own header replaces this on the target. */
#ifndef TINYPSA_BACKEND_CTX_H
#define TINYPSA_BACKEND_CTX_H

#define TINYPSA_SHA256_CTX_SIZE      112
#define TINYPSA_HMAC_SHA256_CTX_SIZE 176
#define TINYPSA_AES_CTX_SIZE         512
#define TINYPSA_CCM_CTX_SIZE         1024
#define TINYPSA_GCM_CTX_SIZE         1024

#endif
