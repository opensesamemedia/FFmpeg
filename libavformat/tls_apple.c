/*
 * Copyright (c) 2015 rcombs
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FFmpeg; if not, write to the Free Software * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>
#include <pthread.h>

#include "avformat.h"
#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "tls.h"
#include "libavcodec/internal.h"
#include "libavutil/avstring.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>

#if CONFIG_NWF
#include <Network/Network.h>
#endif

// We use a private API call here; it's good enough for WebKit.
SecIdentityRef __attribute__((weak)) SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);
#define ioErr -36

#define NWF_CHECK __builtin_available(macOS 10.14, iOS 12.0, watchOS 5.0, tvOS 12.0, *)

typedef struct TLSContext {
    const AVClass *class;
    TLSShared tls_shared;
    SSLContextRef ssl_context;
    CFArrayRef ca_array;
    int lastErr;
#if CONFIG_NWF
    nw_connection_t nw_conn;
    dispatch_semaphore_t semaphore;
    dispatch_semaphore_t state_semaphore;
    pthread_mutex_t state_lock;
    int at_eof;
    nw_listener_state_t nw_listen_state;
    nw_connection_state_t nw_state;
    nw_error_t nw_state_error;
    int tcp_nodelay;
#endif
} TLSContext;

#if CONFIG_NWF
static int nwf_init = 0;
static dispatch_queue_t nwf_queue = NULL;

static int print_nwf_error(void *log_ctx, nw_error_t error, int successRet, const char *func)
{
    if (!error)
        return successRet;

    switch (nw_error_get_error_domain(error)) {
    case nw_error_domain_posix:
        return AVERROR(nw_error_get_error_code(error));
    default:
        av_log(log_ctx, AV_LOG_ERROR, "[%s] Error domain %u, code %i\n", func,
               nw_error_get_error_domain(error),
               nw_error_get_error_code(error));
        return AVERROR(EIO);
    }
}

#define PRINT_NWF_ERROR(err, successRet) print_nwf_error(h, err, successRet, __FUNCTION__)

static int ff_nwf_init(void)
{
    if (NWF_CHECK) {
        int ret = 0;
        ff_lock_avformat();
        if (!nwf_init)
            nwf_queue = dispatch_queue_create("org.ffmpeg.nwf", DISPATCH_QUEUE_SERIAL);
        if (nwf_queue)
            nwf_init++;
        else
            ret = AVERROR(ENOMEM);
        ff_unlock_avformat();

        return ret;
    }

    return AVERROR(EINVAL);
}

static void ff_nwf_deinit(void)
{
    if (NWF_CHECK) {
        ff_lock_avformat();
        nwf_init--;
        if (!nwf_init)
            dispatch_release(nwf_queue);
        ff_unlock_avformat();
    }
}
#endif

static int print_tls_error(URLContext *h, int ret)
{
    TLSContext *c = h->priv_data;
    switch (ret) {
    case errSSLWouldBlock:
        return AVERROR(EAGAIN);
    case errSSLXCertChainInvalid:
        av_log(h, AV_LOG_ERROR, "Invalid certificate chain\n");
        return AVERROR(EIO);
    case ioErr:
        return c->lastErr;
    default:
        av_log(h, AV_LOG_ERROR, "IO Error: %i\n", ret);
        return AVERROR(EIO);
    }
    return AVERROR(EIO);
}

static int import_pem(URLContext *h, char *path, CFArrayRef *array)
{
#if !HAVE_SECITEMIMPORT
    return AVERROR_PATCHWELCOME;
#else
    AVIOContext *s = NULL;
    CFDataRef data = NULL;
    int64_t ret = 0;
    char *buf = NULL;
    SecExternalFormat format = kSecFormatPEMSequence;
    SecExternalFormat type = kSecItemTypeAggregate;
    CFStringRef pathStr = CFStringCreateWithCString(NULL, path, 0x08000100);
    if (!pathStr) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if ((ret = ffio_open_whitelist(&s, path, AVIO_FLAG_READ,
                                   &h->interrupt_callback, NULL,
                                   h->protocol_whitelist, h->protocol_blacklist)) < 0)
        goto end;

    if ((ret = avio_size(s)) < 0)
        goto end;

    if (ret == 0) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    if (!(buf = av_malloc(ret))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if ((ret = avio_read(s, buf, ret)) < 0)
        goto end;

    data = CFDataCreate(kCFAllocatorDefault, buf, ret);

    if (SecItemImport(data, pathStr, &format, &type,
                      0, NULL, NULL, array) != noErr || !array) {
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    if (CFArrayGetCount(*array) == 0) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

end:
    av_free(buf);
    if (pathStr)
        CFRelease(pathStr);
    if (data)
        CFRelease(data);
    if (s)
        avio_close(s);
    return ret;
#endif
}

static int load_ca(URLContext *h)
{
    TLSContext *c = h->priv_data;
    int ret = 0;
    CFArrayRef array = NULL;

    if ((ret = import_pem(h, c->tls_shared.ca_file, &array)) < 0)
        goto end;

    if (!(c->ca_array = CFRetain(array))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

end:
    if (array)
        CFRelease(array);
    return ret;
}

static int load_identity(URLContext *h, SecIdentityRef *identity, CFArrayRef *certArray)
{
#if !HAVE_SECITEMIMPORT
    return AVERROR_PATCHWELCOME;
#else
    TLSContext *c = h->priv_data;
    int ret = 0;
    CFArrayRef keyArray = NULL;

    if ((ret = import_pem(h, c->tls_shared.cert_file, certArray)) < 0)
        goto end;

    if ((ret = import_pem(h, c->tls_shared.key_file, &keyArray)) < 0)
        goto end;

    if (!SecIdentityCreate) {
        ret = AVERROR_PATCHWELCOME;
        goto end;
    }

    if (CFGetTypeID(CFArrayGetValueAtIndex(*certArray, 0)) != SecCertificateGetTypeID() ||
        CFGetTypeID(CFArrayGetValueAtIndex(keyArray, 0)) != SecKeyGetTypeID()) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    if (!(*identity = SecIdentityCreate(kCFAllocatorDefault,
                                 (SecCertificateRef)CFArrayGetValueAtIndex(*certArray, 0),
                                 (SecKeyRef)CFArrayGetValueAtIndex(keyArray, 0)))) {
        ret = AVERROR_UNKNOWN;
        goto end;
    }

end:
    if (keyArray)
        CFRelease(keyArray);
    return ret;
#endif
}

static int load_cert(URLContext *h)
{
    TLSContext *c = h->priv_data;
    int ret = 0;
    SecIdentityRef id = NULL;
    CFArrayRef certArray = NULL;
    CFMutableArrayRef outArray = NULL;

    if ((ret = load_identity(h, &id, &certArray)) < 0)
        goto end;

    if (!(outArray = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, certArray))) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    CFArraySetValueAtIndex(outArray, 0, id);

    SSLSetCertificate(c->ssl_context, outArray);

end:
    if (certArray)
        CFRelease(certArray);
    if (outArray)
        CFRelease(outArray);
    if (id)
        CFRelease(id);
    return ret;
}

static OSStatus tls_read_cb(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    URLContext *h = (URLContext*)connection;
    TLSContext *c = h->priv_data;
    size_t requested = *dataLength;
    int read = ffurl_read(c->tls_shared.tcp, data, requested);
    if (read <= 0) {
        *dataLength = 0;
        switch(AVUNERROR(read)) {
            case ENOENT:
            case 0:
                return errSSLClosedGraceful;
            case ECONNRESET:
                return errSSLClosedAbort;
            case EAGAIN:
                return errSSLWouldBlock;
            default:
                c->lastErr = read;
                return ioErr;
        }
    } else {
        *dataLength = read;
        if (read < requested)
            return errSSLWouldBlock;
        else
            return noErr;
    }
}

static OSStatus tls_write_cb(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    URLContext *h = (URLContext*)connection;
    TLSContext *c = h->priv_data;
    int written = ffurl_write(c->tls_shared.tcp, data, *dataLength);
    if (written <= 0) {
        *dataLength = 0;
        switch(AVUNERROR(written)) {
            case EAGAIN:
                return errSSLWouldBlock;
            default:
                c->lastErr = written;
                return ioErr;
        }
    } else {
        *dataLength = written;
        return noErr;
    }
}

static int tls_close(URLContext *h)
{
    TLSContext *c = h->priv_data;

#if CONFIG_NWF
    if (NWF_CHECK) {
        if (c->nw_conn) {
            nw_connection_cancel(c->nw_conn);
            nw_release(c->nw_conn);
        }

        pthread_mutex_lock(&c->state_lock);
        while (c->nw_state != nw_connection_state_cancelled &&
               c->nw_state != nw_connection_state_failed &&
               c->nw_state != nw_connection_state_invalid) {
            pthread_mutex_unlock(&c->state_lock);
            dispatch_semaphore_wait(c->state_semaphore, DISPATCH_TIME_FOREVER);
            pthread_mutex_lock(&c->state_lock);
        }
        pthread_mutex_unlock(&c->state_lock);

        if (c->semaphore)
            dispatch_release(c->semaphore);
        if (c->state_semaphore)
            dispatch_release(c->state_semaphore);

        pthread_mutex_destroy(&c->state_lock);

        ff_nwf_deinit();
    }
#endif

    if (c->ssl_context) {
        SSLClose(c->ssl_context);
        CFRelease(c->ssl_context);
    }
    if (c->ca_array)
        CFRelease(c->ca_array);
    ffurl_closep(&c->tls_shared.tcp);
    return 0;
}

#define CHECK_ERROR(func, ...) do {                                     \
        OSStatus status = func(__VA_ARGS__);                            \
        if (status != noErr) {                                          \
            ret = AVERROR_UNKNOWN;                                      \
            av_log(h, AV_LOG_ERROR, #func ": Error %i\n", (int)status); \
            goto fail;                                                  \
        }                                                               \
    } while (0)

static int tls_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    TLSContext *c = h->priv_data;
    TLSShared *s = &c->tls_shared;
    int ret = 0;

    if (s->ca_file) {
        if ((ret = load_ca(h)) < 0)
            goto fail;
    }

#if CONFIG_NWF
    if (NWF_CHECK) {
        int port;
        char portStr[8];
        SecIdentityRef identity = NULL;
        CFArrayRef certArray = NULL;
        nw_endpoint_t endpoint = NULL;
        nw_parameters_t parameters = NULL;
        bool finished = false;

        if ((ret = ff_nwf_init()) < 0)
            return ret;

        if ((ret = AVERROR(pthread_mutex_init(&c->state_lock, NULL))) < 0)
            goto nwf_fail;

        if ((ret = ff_tls_process_underlying(s, h, uri, &port)) < 0)
            goto nwf_fail;

        snprintf(portStr, sizeof(portStr), "%i", port);

        if (!(c->semaphore = dispatch_semaphore_create(0))) {
            ret = AVERROR(ENOMEM);
            goto nwf_fail;
        }

        if (!(c->state_semaphore = dispatch_semaphore_create(0))) {
            ret = AVERROR(ENOMEM);
            goto nwf_fail;
        }

        if (!(endpoint = nw_endpoint_create_host(s->underlying_host, portStr))) {
            ret = AVERROR(ENOMEM);
            goto nwf_fail;
        }

        if (s->cert_file && (ret = load_identity(h, &identity, &certArray)) < 0)
            goto nwf_fail;

        if (!(parameters = nw_parameters_create_secure_tcp(^(nw_protocol_options_t tls_options) {
            sec_protocol_options_t options = nw_tls_copy_sec_protocol_options(tls_options);
            sec_protocol_options_set_tls_server_name(options, s->host);
            sec_protocol_options_set_peer_authentication_required(options, s->verify);
            if (s->ca_file || !s->verify)
                sec_protocol_options_set_verify_block(options, ^(sec_protocol_metadata_t metadata, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete) {
                    bool succ = false;
                    SecTrustRef peerTrust = NULL;
                    SecTrustResultType trustResult;

                    // set_peer_authentication_required is buggy; seems to no-op
                    if (!s->verify)
                        complete(true);

                    if (!(peerTrust = sec_trust_copy_ref(trust_ref)))
                        goto verify_fail;

                    if (SecTrustSetAnchorCertificates(peerTrust, c->ca_array) != noErr)
                        goto verify_fail;

                    if (SecTrustEvaluate(peerTrust, &trustResult) != noErr)
                        goto verify_fail;

                    succ = (trustResult == kSecTrustResultProceed ||
                            trustResult == kSecTrustResultUnspecified);

verify_fail:
                    if (peerTrust)
                        CFRelease(peerTrust);
                    complete(succ);
                }, nwf_queue);
            if (identity) {
                sec_identity_t sec_id = sec_identity_create_with_certificates(identity, certArray);
                if (sec_id) {
                    sec_protocol_options_set_local_identity(options, sec_id);
                    nw_release(sec_id);
                }
            }
        }, ^(nw_protocol_options_t tcp_options) {
            nw_tcp_options_set_no_delay(tcp_options, c->tcp_nodelay);
        }))) {
            ret = AVERROR(ENOMEM);
            goto nwf_fail;
        }

        if (s->listen) {
            nw_listener_t listener;

            nw_parameters_set_local_endpoint(parameters, endpoint);

            listener = nw_listener_create(parameters);
            if (!listener) {
                ret = AVERROR(ENOMEM);
                goto nwf_fail;
            }

            nw_listener_set_queue(listener, nwf_queue);

            nw_listener_set_new_connection_handler(listener, ^(nw_connection_t connection) {
                pthread_mutex_lock(&c->state_lock);
                if (!c->nw_conn) {
                    nw_retain(connection);
                    c->nw_conn = connection;
                    dispatch_semaphore_signal(c->state_semaphore);
                }
                pthread_mutex_unlock(&c->state_lock);
            });
            nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
                pthread_mutex_lock(&c->state_lock);
                c->nw_listen_state = state;
                c->nw_state_error = error;
                dispatch_semaphore_signal(c->state_semaphore);
                pthread_mutex_unlock(&c->state_lock);
            });

            nw_listener_start(listener);

            while (!finished) {
                dispatch_semaphore_wait(c->state_semaphore, DISPATCH_TIME_FOREVER);
                pthread_mutex_lock(&c->state_lock);
                switch (c->nw_listen_state) {
                case nw_listener_state_invalid:
                    ret = AVERROR_UNKNOWN;
                    finished = true;
                    break;
                case nw_listener_state_waiting:
                    break;
                case nw_listener_state_ready:
                    ret = 0;
                    if (c->nw_conn)
                        finished = true;
                    break;
                case nw_listener_state_failed:
                default:
                    ret = PRINT_NWF_ERROR(c->nw_state_error, AVERROR_UNKNOWN);
                    finished = true;
                    break;
                case nw_listener_state_cancelled:
                    ret = AVERROR(EIO);
                    finished = true;
                    break;
                }
                pthread_mutex_unlock(&c->state_lock);
            }

            finished = false;

            nw_listener_cancel(listener);
            nw_release(listener);

            pthread_mutex_lock(&c->state_lock);
            while (c->nw_listen_state != nw_listener_state_cancelled &&
                   c->nw_listen_state != nw_listener_state_failed &&
                   c->nw_listen_state != nw_listener_state_invalid) {
                pthread_mutex_unlock(&c->state_lock);
                dispatch_semaphore_wait(c->state_semaphore, DISPATCH_TIME_FOREVER);
                pthread_mutex_lock(&c->state_lock);
            }
            pthread_mutex_unlock(&c->state_lock);

            if (!c->nw_conn)
                goto nwf_fail;
        } else {
            if (!(c->nw_conn = nw_connection_create(endpoint, parameters))) {
                ret = AVERROR(ENOMEM);
                goto nwf_fail;
            }
        }

        nw_connection_set_state_changed_handler(c->nw_conn, ^(nw_connection_state_t state, nw_error_t error) {
            pthread_mutex_lock(&c->state_lock);
            c->nw_state = state;
            c->nw_state_error = error;
            dispatch_semaphore_signal(c->state_semaphore);
            pthread_mutex_unlock(&c->state_lock);
        });

        nw_connection_set_queue(c->nw_conn, nwf_queue);

        nw_connection_start(c->nw_conn);

        while (!finished) {
            dispatch_semaphore_wait(c->state_semaphore, DISPATCH_TIME_FOREVER);
            pthread_mutex_lock(&c->state_lock);
            switch (c->nw_state) {
            case nw_connection_state_invalid:
                ret = AVERROR_UNKNOWN;
                finished = true;
                break;
            case nw_connection_state_waiting:
            case nw_connection_state_preparing:
                break;
            case nw_connection_state_ready:
                ret = 0;
                finished = true;
                break;
            case nw_connection_state_failed:
            default:
                ret = PRINT_NWF_ERROR(c->nw_state_error, AVERROR_UNKNOWN);
                finished = true;
                break;
            case nw_connection_state_cancelled:
                ret = AVERROR(EIO);
                finished = true;
                break;
            }
            pthread_mutex_unlock(&c->state_lock);
        }

nwf_fail:
        if (endpoint)
            nw_release(endpoint);
        if (parameters)
            nw_release(parameters);
        if (certArray)
            CFRelease(certArray);
        if (identity)
            CFRelease(identity);
        if (ret < 0)
            tls_close(h);
        return ret;
    }
#endif

    if ((ret = ff_tls_open_underlying(s, h, uri, options)) < 0)
        goto fail;

    c->ssl_context = SSLCreateContext(NULL, s->listen ? kSSLServerSide : kSSLClientSide, kSSLStreamType);
    if (!c->ssl_context) {
        av_log(h, AV_LOG_ERROR, "Unable to create SSL context\n");
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    if (s->ca_file || !s->verify)
        CHECK_ERROR(SSLSetSessionOption, c->ssl_context, kSSLSessionOptionBreakOnServerAuth, true);
    if (s->cert_file)
        if ((ret = load_cert(h)) < 0)
            goto fail;
    CHECK_ERROR(SSLSetPeerDomainName, c->ssl_context, s->host, strlen(s->host));
    CHECK_ERROR(SSLSetIOFuncs, c->ssl_context, tls_read_cb, tls_write_cb);
    CHECK_ERROR(SSLSetConnection, c->ssl_context, h);
    while (1) {
        OSStatus status = SSLHandshake(c->ssl_context);
        if (status == errSSLServerAuthCompleted) {
            SecTrustRef peerTrust;
            SecTrustResultType trustResult;
            if (!s->verify)
                continue;

            if (SSLCopyPeerTrust(c->ssl_context, &peerTrust) != noErr) {
                ret = AVERROR(ENOMEM);
                goto fail;
            }

            if (SecTrustSetAnchorCertificates(peerTrust, c->ca_array) != noErr) {
                ret = AVERROR_UNKNOWN;
                goto fail;
            }

            if (SecTrustEvaluate(peerTrust, &trustResult) != noErr) {
                ret = AVERROR_UNKNOWN;
                goto fail;
            }

            if (trustResult == kSecTrustResultProceed ||
                trustResult == kSecTrustResultUnspecified) {
                // certificate is trusted
                status = errSSLWouldBlock; // so we call SSLHandshake again
            } else if (trustResult == kSecTrustResultRecoverableTrustFailure) {
                // not trusted, for some reason other than being expired
                status = errSSLXCertChainInvalid;
            } else {
                // cannot use this certificate (fatal)
                status = errSSLBadCert;
            }

            if (peerTrust)
                CFRelease(peerTrust);
        }
        if (status == noErr) {
            break;
        } else if (status != errSSLWouldBlock) {
            av_log(h, AV_LOG_ERROR, "Unable to negotiate TLS/SSL session: %i\n", (int)status);
            ret = AVERROR(EIO);
            goto fail;
        }
    }

    return 0;
fail:
    tls_close(h);
    return ret;
}

static int map_ssl_error(OSStatus status, size_t processed)
{
    switch (status) {
    case noErr:
        return processed;
    case errSSLClosedGraceful:
    case errSSLClosedNoNotify:
        return 0;
    case errSSLWouldBlock:
        if (processed > 0)
            return processed;
    default:
        return (int)status;
    }
}

static int tls_read(URLContext *h, uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    size_t available = 0, processed = 0;
    int ret;

#if CONFIG_NWF
    if (NWF_CHECK) {
        __block nw_error_t error;
        __block int gotSize = 0;

        if (c->at_eof)
            return AVERROR_EOF;

        nw_connection_receive(c->nw_conn, 1, size, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t inError) {
            if (is_complete)
                c->at_eof = 1;

            if (content) {
                gotSize = dispatch_data_get_size(content);

                dispatch_data_apply(content, ^(dispatch_data_t region, size_t offset, const void *buffer, size_t inSize) {
                    memcpy(buf + offset, buffer, inSize);
                    return (bool)true;
                });
            }

            error = inError;
            dispatch_semaphore_signal(c->semaphore);
        });

        dispatch_semaphore_wait(c->semaphore, DISPATCH_TIME_FOREVER);

        if (c->at_eof && !gotSize && !error)
            return AVERROR_EOF;

        return PRINT_NWF_ERROR(error, gotSize);
    }
#endif

    SSLGetBufferedReadSize(c->ssl_context, &available);
    if (available)
        size = FFMIN(available, size);
    ret = SSLRead(c->ssl_context, buf, size, &processed);
    ret = map_ssl_error(ret, processed);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return print_tls_error(h, ret);
}

static int tls_write(URLContext *h, const uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    size_t processed = 0;
    int ret;

#if CONFIG_NWF
    if (NWF_CHECK) {
        __block nw_error_t error;
        dispatch_data_t content = dispatch_data_create(buf, size, nwf_queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(c->nw_conn, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t inError) {
            error = inError;
            dispatch_semaphore_signal(c->semaphore);
        });
        dispatch_release(content);

        dispatch_semaphore_wait(c->semaphore, DISPATCH_TIME_FOREVER);

        return PRINT_NWF_ERROR(error, size);
    }
#endif

    ret = SSLWrite(c->ssl_context, buf, size, &processed);
    ret = map_ssl_error(ret, processed);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return print_tls_error(h, ret);
}

static int tls_get_file_handle(URLContext *h)
{
    TLSContext *c = h->priv_data;
#if CONFIG_NWF
    if (NWF_CHECK) // Network.framework doesn't expose file handles
        return -1;
#endif
    return ffurl_get_file_handle(c->tls_shared.tcp);
}

static int tls_get_short_seek(URLContext *h)
{
    TLSContext *s = h->priv_data;
    return ffurl_get_short_seek(s->tls_shared.tcp);
}

#define OFFSET(v) offsetof(TLSContext, v)

static const AVOption options[] = {
    TLS_COMMON_OPTIONS(TLSContext, tls_shared),
#if CONFIG_NWF
    { "tcp_nodelay", "Use TCP_NODELAY to disable nagle's algorithm", OFFSET(tcp_nodelay), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, .flags = TLS_OPTFL },
#endif
     { NULL }
    { NULL }
};

static const AVClass tls_class = {
    .class_name = "tls",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_tls_protocol = {
    .name           = "tls",
    .url_open2      = tls_open,
    .url_read       = tls_read,
    .url_write      = tls_write,
    .url_close      = tls_close,
    .url_get_file_handle = tls_get_file_handle,
    .url_get_short_seek  = tls_get_short_seek,
    .priv_data_size = sizeof(TLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &tls_class,
};
