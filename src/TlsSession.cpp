#include "pch.h"
#include "TlsSession.h"

#include <bearssl.h>

#include "Kernel.h"
#include "Memory.h"
#include "SystemSocket.h"

namespace XexUtils
{
namespace TlsSession
{

static br_hmac_drbg_context s_drbg = {};

static int SocketReadCallback(void *pContext, uint8_t *buffer, size_t maxSize)
{
    SOCKET socket = Memory::Read<SOCKET>(pContext);

    return recv(socket, reinterpret_cast<char *>(buffer), maxSize, 0);
}

static int SocketWriteCallback(void *pContext, const uint8_t *buffer, size_t maxSize)
{
    SOCKET socket = Memory::Read<SOCKET>(pContext);

    return send(socket, reinterpret_cast<const char *>(buffer), maxSize, 0);
}

bool InitContext(TlsSessionContext*& context)
{
    context = (TlsSessionContext*)malloc(sizeof(TlsSessionContext));
    if(!context) {
        return false;
	}

    memset(context, 0, sizeof(TlsSessionContext));
    return true;
}

void FreeContext(TlsSessionContext*& context)
{
    memset(context, 0, sizeof(TlsSessionContext));
    free(context);
}

HRESULT AddECTrustAnchor(TlsSessionContext* context, const uint8_t *dn, size_t dnSize, const uint8_t *q, size_t qSize, EllipticCurveType curveType)
{
    XASSERT(dn != nullptr);
    XASSERT(q != nullptr);

    if (context->TrustAnchorCount == MAX_ANCHORS)
    {
        DebugPrint("[XexUtils][TlsSession]: Error: Max amount of trust anchors reached.");
        return E_FAIL;
    }

    context->TrustAnchors[context->TrustAnchorCount].dn.data = const_cast<uint8_t *>(dn);
    context->TrustAnchors[context->TrustAnchorCount].dn.len = dnSize;
    context->TrustAnchors[context->TrustAnchorCount].flags = BR_X509_TA_CA;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key_type = BR_KEYTYPE_EC;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.ec.curve = curveType;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.ec.q = const_cast<uint8_t *>(q);
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.ec.qlen = qSize;

    context->TrustAnchorCount++;

    return S_OK;
}

HRESULT AddRsaTrustAnchor(TlsSessionContext* context, const uint8_t *dn, size_t dnSize, const uint8_t *n, size_t nSize, const uint8_t *e, size_t eSize)
{
    XASSERT(dn != nullptr);
    XASSERT(n != nullptr);
    XASSERT(e != nullptr);

    if (context->TrustAnchorCount == MAX_ANCHORS)
    {
        DebugPrint("[XexUtils][TlsSession]: Error: Max amount of trust anchors reached.");
        return E_FAIL;
    }

    context->TrustAnchors[context->TrustAnchorCount].dn.data = const_cast<uint8_t *>(dn);
    context->TrustAnchors[context->TrustAnchorCount].dn.len = dnSize;
    context->TrustAnchors[context->TrustAnchorCount].flags = BR_X509_TA_CA;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key_type = BR_KEYTYPE_RSA;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.rsa.n = const_cast<uint8_t *>(n);
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.rsa.nlen = nSize;
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.rsa.e = const_cast<uint8_t *>(e);
    context->TrustAnchors[context->TrustAnchorCount].pkey.key.rsa.elen = eSize;

    context->TrustAnchorCount++;

    return S_OK;
}

void Start(TlsSessionContext* context, const SOCKET &sock, const std::string &domain)
{
    XASSERT(sock != INVALID_SOCKET);
    XASSERT(domain.empty() == false);

    br_ssl_client_init_full(&context->SslClientContext, &context->x509Context, context->TrustAnchors, context->TrustAnchorCount);

    br_ssl_engine_set_buffer(&context->SslClientContext.eng, context->IoBuffer, sizeof(context->IoBuffer), 1);

    br_ssl_client_reset(&context->SslClientContext, domain.c_str(), 0);

    br_sslio_init(
        &context->IoContext,
        &context->SslClientContext.eng,
        SocketReadCallback,
        const_cast<SOCKET *>(&sock),
        SocketWriteCallback,
        const_cast<SOCKET *>(&sock)
    );
}

int Send(TlsSessionContext* context, const char *buffer, size_t size)
{
    XASSERT(buffer != nullptr);

    if (br_sslio_write_all(&context->IoContext, buffer, size) != 0)
    {
        DebugPrint(
            "[XexUtils][TlsSession]: Error: SSL write error: %d",
            br_ssl_engine_last_error(&context->SslClientContext.eng)
        );
        return SOCKET_ERROR;
    }

    if (br_sslio_flush(&context->IoContext) != 0)
    {
        DebugPrint(
            "[XexUtils][TlsSession]: Error: SSL flush error: %d",
            br_ssl_engine_last_error(&context->SslClientContext.eng)
        );
        return SOCKET_ERROR;
    }

    return size;
}

int Receive(TlsSessionContext* context, char *buffer, size_t maxSize)
{
    XASSERT(buffer != nullptr);

    int bytesRead = br_sslio_read(&context->IoContext, buffer, maxSize);

#ifndef NDEBUG
    int lastSslError = br_ssl_engine_last_error(&context->SslClientContext.eng);
    if (bytesRead < 0 && lastSslError != 0)
        DebugPrint("[XexUtils][Socket]: Error: SSL read error: %d", lastSslError);
#endif

    return bytesRead;
}

// Custom enthropy function
static int CustomSeeder(const br_prng_class **ppContext)
{
    uint8_t seed[32] = {};
    XeCryptRandom(seed, sizeof(seed));
    br_hmac_drbg_init(&s_drbg, &br_sha256_vtable, seed, sizeof(seed));
    *ppContext = s_drbg.vtable;

    return 1;
}

}
}

// Replace the original br_prng_seeder_system function from BearSSL with our own because the original
// one obviously doesn't support the Xbox 360
br_prng_seeder br_prng_seeder_system(const char **name)
{
    if (name)
        *name = "XeCryptRandom";

    return &XexUtils::TlsSession::CustomSeeder;
}
