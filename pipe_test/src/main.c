#define CONVEY_NAMESPACE_CLEAN 1

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/transport/tls/tls.h>

static const char* g_cert =
"-----BEGIN CERTIFICATE-----\n"
"MIIDbTCCAlWgAwIBAgIUP+1Cik+XGy6/6IPJLUjANJTuMQkwDQYJKoZIhvcNAQEL\n"
"BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n"
"GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMTExMjQyMjUyMjVaGA8zMDIx\n"
"MDMyNzIyNTIyNVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n"
"ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\n"
"AQEBBQADggEPADCCAQoCggEBALROqLCKFBGkj9f2MJKns9Jt6eLXBks2PijcqUgg\n"
"SLev8vNDIIGp7CjSaqtvNSfu2IqiOOzILq44zwtn4E/T37vazJtKUQETPT2o82aM\n"
"Cziw95yQGSEj55fsK8PsS0oQQQQW2VYGPOR0UXVHC7UU5wcChpSvHhfb66LyNu9u\n"
"gJ+/y3B5PWdXqDU5zjWyB8dEH3tSa2bwTv4j3qNw3Yd2NikdjYq/4/qijEI7O6BK\n"
"mSq0x4/CLtA8h9npl7y9e/gkh1VdKnkGQlK01Ev2jJ4QHS5bUv4c8RnHEdaprz2W\n"
"zwCkoxx6A6HY5jqjlwMQmHjaAgUiFC1uVA8WCP09LcDO/5UCAwEAAaNTMFEwHQYD\n"
"VR0OBBYEFKUzfH9XdNgHVdwseRii1gLJs+OEMB8GA1UdIwQYMBaAFKUzfH9XdNgH\n"
"VdwseRii1gLJs+OEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
"AHX9FDMLBUEox8thgEs2oJKJl7K2L/Cnu2ZCpyfgeNtkMlwsoM0SUD5ENoyCiCkf\n"
"IvsVyTLVtZVDHyhMFQV7GMIHV1INvqul/Sb3mO3+mIGR8Vnd40iksBJ3yneaye1W\n"
"EBM0JzgrZZITPeEdCXrTLgpDBkFy1x/BJecAjp2cNNNnxv+oz44Bd9Cqxw5SxodH\n"
"NphO9v/qKtpaDvOLYK/Ft7WgPxpYNL688vIOGe4pakt0iCFkqdptB2S2h/VlOmo8\n"
"9Z7d8tsp2JeJcLBOUhQidzBJuvyO84h3XTxc6WfUc14UzjZZQNIogarC32OGDbh4\n"
"9R11I/4rLl7my2ftqJKssEs=\n"
"-----END CERTIFICATE-----\n";

static const char* g_key =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAtE6osIoUEaSP1/Ywkqez0m3p4tcGSzY+KNypSCBIt6/y80Mg\n"
"gansKNJqq281J+7YiqI47MgurjjPC2fgT9Pfu9rMm0pRARM9PajzZowLOLD3nJAZ\n"
"ISPnl+wrw+xLShBBBBbZVgY85HRRdUcLtRTnBwKGlK8eF9vrovI2726An7/LcHk9\n"
"Z1eoNTnONbIHx0Qfe1JrZvBO/iPeo3Ddh3Y2KR2Nir/j+qKMQjs7oEqZKrTHj8Iu\n"
"0DyH2emXvL17+CSHVV0qeQZCUrTUS/aMnhAdLltS/hzxGccR1qmvPZbPAKSjHHoD\n"
"odjmOqOXAxCYeNoCBSIULW5UDxYI/T0twM7/lQIDAQABAoIBAH9ELgk9zOCPGQDE\n"
"QpChUmmrLzTvtP+Nb96DsfC46NrOlFtj/CPJfmlp6+TJf+mJyso/qpJm0ZwjePCC\n"
"B3ARCpCb5WOO1xI9NDK7d+Hf42PGdV/KzhH4N9Wh21pVBOdoBZwPTKRNjtlpyL1Q\n"
"wlC0SkVGYRu9Zy5MCkxfTqs9ggg+tjfCQBZ8eltOHZt/UjosiJEUcKGtfddt4cNh\n"
"huESzhDTbUj4xZQVTd3wJ39lk0FCy1+UHm8NTQQHMsKzWaTh/mnuuInWomA/s9KM\n"
"maJeuR+FMWlEuvCGZl2KTCnUK12j2pvoHkCk4VIvhxnjQv7dx1V6jkUq78BZ8KuU\n"
"Qv8TRoECgYEA5U9PfxRwha3UZE8zRFPraFBv4R8JmIUIgqwwGdHADNWEQ1Wjfp0n\n"
"IJsQCUqdcuHWH1HSvXSW7RlDaujJfk+jJ6yhOGliLfqAgw/lqjo3qCIQKlyiBSJF\n"
"I+rJj0HreIrc2TafHOR9r/zUewKXX2sl/axNKs5MGhqNM+5Z2A2iiQUCgYEAyUs7\n"
"Nc17VeMjnkn+msFJI2KNnUBaF4xsNPy2r3C5aMLnrOQGGeskH+qbrSbRbZJAr6UE\n"
"if1bZuD9Wy7KXGFCpzdo+XwgYDxBnv/ft7oqaP5EquFxgzKpFZRjNYhQI5GfJO+5\n"
"Wi2r9KqmiWebQM/N/kkgVTCj0hf894RAcEdYIVECgYEA0uitn563F90YOuK1rqTZ\n"
"ImrJXG/lrYi+mSGyZC0NzUAdlKkR5YS51j2I9GLSijW5cbkacfLoVk8kORK/MRQi\n"
"Zn1bE72p9cwvo1xdysIdKuGZqLzmsH4ixbRPixoAcDCYjJi2pCZsjA+phzKM89Bj\n"
"cvylRTfVuzSspxUVQajY09kCgYBuwnuRDkDIMJRfu71hr+srkkXz+f3YqUa9HTT0\n"
"ciVDNMO/yTRmPJGDEleYvhxMm0YGn9lQiF0rza765lMo48eGNSII7TjvWxiMgaS6\n"
"9q/xV7+2+xe3pj+NhTnVsezOtYkJDPNDYJAWr3O1dZHi5rUlL12gIoRxzQs/ssC2\n"
"RzuCEQKBgQDHb1XtUVA8MRaTpTYhnPG8CKGbOXGNWAtM3YkSWu6pauSImAYbBYqZ\n"
"zbb7RxqzHxncT2Y8NO1yx5ta08MOM/sQ41a15pj4AI27j6b0H5TaEw3hozuJ/CLS\n"
"AzE2Vop7e6k91sUoFOGqOHE64ZS95HQOdxR+a2eqmss6zMoe3pKkLQ==\n"
"-----END RSA PRIVATE KEY-----\n";

// #define SERVER_URL "tls+tcp://127.0.0.1:20000"
#define SERVER_URL "tcp://127.0.0.1:20000"

#define GOTO_LABEL_WITH_NNG_ERR_IF(label, condition, status) \
    do { \
        if (condition) \
        { \
            printf("Failed condition %s at line %d with error %s\n", #condition, __LINE__, nng_strerror(status)); \
            goto label; \
        } \
    } while(0)


static int init_tls_listener(nng_listener * listener)
{
    int status;
    nng_tls_config* config;

    status = nng_tls_config_alloc(&config, NNG_TLS_MODE_SERVER);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_tls_config_own_cert(config, g_cert, g_key, NULL);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_listener_setopt_ptr(*listener, NNG_OPT_TLS_CONFIG, (void*)config);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_tls_config_auth_mode(config, NNG_TLS_AUTH_MODE_NONE);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

end:
    return status;
}

static int init_tls_dialer(nng_dialer* dialer, nng_socket* sock, const char* target_url)
{
	int status;
	nng_tls_config* config;

    status = nng_dialer_create(dialer, *sock, target_url);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_tls_config_alloc(&config, NNG_TLS_MODE_CLIENT);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_tls_config_auth_mode(config, NNG_TLS_AUTH_MODE_NONE);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_dialer_setopt_ptr(*dialer, NNG_OPT_TLS_CONFIG, (void*)config);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

end:
	return status;
}

static void notify(nng_pipe pipe, nng_pipe_ev action, void* arg)
{
    if (action == NNG_PIPE_EV_ADD_POST)
    {
        printf("server: new connection.\n");
    }
    else if (action == NNG_PIPE_EV_REM_POST)
    {
        printf("server: connection removed.\n");
    }
    else
    {
        printf("huh?\n");
    }
}

static void client_notify(nng_pipe pipe, nng_pipe_ev action, void* arg)
{
	if (action == NNG_PIPE_EV_ADD_POST)
	{
		printf("client: new connection.\n");
	}
	else if (action == NNG_PIPE_EV_REM_POST)
	{
		printf("client: connection removed.\n");
	}
	else
	{
		printf("huh?\n");
	}
}

static void server_thread(void* arg)
{
    uint32_t status = 0;
    nng_socket sock = {0};
    nng_listener listener = {0};
	char* buf = NULL;
	size_t sz;

    status = nng_pair1_open(&sock);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_listener_create(&listener, sock, SERVER_URL);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

//     status = init_tls_listener(&listener);
//     GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    // Create the notify callback
    status = nng_pipe_notify(sock, NNG_PIPE_EV_ADD_POST, notify, NULL);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_pipe_notify(sock, NNG_PIPE_EV_REM_POST, notify, NULL);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_listener_start(listener, 0);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

// If this gets uncommented, the pipe close notify works.
// 	status = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC);
//     GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);
//
//     printf("Received %s\n", buf);

	nng_free(buf, sz);

end:

    return;
}

static void closing_thread(void* arg)
{
    nng_socket* sock = arg;

    nng_msleep(2000);
    nng_close(*sock);
    printf("Should have received a disconnect notify now.\n");
}

int main( int argc, char* argv[] )
{
    int status = 0;
    nng_thread *server_thread_handle;
    nng_thread* close_thread_handle;
    nng_socket sock = {0};
    nng_dialer dialer = {0};

    // Start the pipe server thread
	status = nng_thread_create(&server_thread_handle, server_thread, NULL);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	// Sleep a bit to let everything actually setup.
	nng_msleep(100);

    // Now dial and disconnect
	status = nng_pair1_open(&sock);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	// Create the notify callback
	status = nng_pipe_notify(sock, NNG_PIPE_EV_ADD_POST, client_notify, NULL);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_pipe_notify(sock, NNG_PIPE_EV_REM_POST, client_notify, NULL);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_dialer_create(&dialer, sock, SERVER_URL);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

//     status = init_tls_dialer(&dialer, &sock, SERVER_URL);
//     GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    status = nng_dialer_start(dialer, 0);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    printf("Connected\n");

    status = nng_send(sock, "Hello World", strlen("Hello World") + 1, 0);
    GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

	status = nng_thread_create(&close_thread_handle, closing_thread, &sock);
	GOTO_LABEL_WITH_NNG_ERR_IF(end, status != 0, status);

    // Wait on close thread
    nng_thread_destroy(close_thread_handle);

    nng_msleep(3000);

    nng_thread_destroy(server_thread_handle);

end:

    return 0;
}
