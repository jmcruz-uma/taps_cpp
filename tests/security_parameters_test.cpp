// Tests for the SecurityParameters API surface: defaults mean "no security",
// require_tls() / set_allowed_protocols() are the enable signal, and every setter
// is readable back through the provider-facing accessors. Nothing here exercises a
// TLS handshake — SecurityParameters is pure configuration.

#include "taps/taps_api.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace taps;

static int g_failures = 0;

#define CHECK(cond)                                                             \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
            ++g_failures;                                                      \
        }                                                                     \
    } while (0)

static void test_defaults() {
    SecurityParameters sp;
    CHECK(!sp.is_enabled());
    CHECK(sp.allowed_protocols().empty());
    CHECK(sp.min_tls_version() == TLSVersion::TLS_1_2);
    CHECK(sp.max_tls_version() == TLSVersion::TLS_1_3);
    CHECK(sp.trust_anchors().empty());
    CHECK(sp.server_name().empty());
    CHECK(sp.alpn_protocols().empty());
    CHECK(sp.ciphersuites().empty());
    CHECK(sp.supported_groups().empty());
    CHECK(sp.certificate_chain_file().empty());
    CHECK(sp.private_key_file().empty());
}

static void test_enable_signal() {
    SecurityParameters sp;
    sp.require_tls();
    CHECK(sp.is_enabled());
    CHECK(sp.allowed_protocols().size() == 1);
    CHECK(sp.allowed_protocols().front() == SecurityProtocol::TLS);

    SecurityParameters sp2;
    sp2.set_allowed_protocols({SecurityProtocol::TLS});
    CHECK(sp2.is_enabled());

    SecurityParameters sp3;
    sp3.set_allowed_protocols({});
    CHECK(!sp3.is_enabled());
}

static void test_setters_roundtrip() {
    SecurityParameters sp;

    sp.set_tls_version_range(TLSVersion::TLS_1_3, TLSVersion::TLS_1_3);
    CHECK(sp.min_tls_version() == TLSVersion::TLS_1_3);
    CHECK(sp.max_tls_version() == TLSVersion::TLS_1_3);

    sp.add_trust_anchor("ca.pem");
    sp.add_trust_anchor("ca2.pem");
    CHECK(sp.trust_anchors().size() == 2);
    CHECK(sp.trust_anchors()[0] == "ca.pem");
    CHECK(sp.trust_anchors()[1] == "ca2.pem");

    sp.set_server_name("taps-bench.test");
    CHECK(sp.server_name() == "taps-bench.test");

    sp.add_alpn("taps-bench/1");
    sp.add_alpn("http/1.1");
    CHECK(sp.alpn_protocols().size() == 2);
    CHECK(sp.alpn_protocols().front() == "taps-bench/1");

    sp.set_ciphersuites({"TLS_AES_128_GCM_SHA256"});
    CHECK(sp.ciphersuites().size() == 1);
    CHECK(sp.ciphersuites().front() == "TLS_AES_128_GCM_SHA256");

    sp.set_supported_groups({"X25519"});
    CHECK(sp.supported_groups().size() == 1);
    CHECK(sp.supported_groups().front() == "X25519");

    sp.set_certificate_chain_file("srv.crt");
    sp.set_private_key_file("srv.key");
    CHECK(sp.certificate_chain_file() == "srv.crt");
    CHECK(sp.private_key_file() == "srv.key");
}

static void test_copyable() {
    SecurityParameters sp;
    sp.require_tls();
    sp.add_trust_anchor("ca.pem");
    sp.add_alpn("taps-bench/1");

    SecurityParameters copy = sp;
    CHECK(copy.is_enabled());
    CHECK(copy.trust_anchors().size() == 1);
    CHECK(copy.alpn_protocols().front() == "taps-bench/1");
}

int main() {
    test_defaults();
    test_enable_signal();
    test_setters_roundtrip();
    test_copyable();

    if (g_failures == 0) {
        std::printf("security_parameters_test: all checks passed\n");
        return 0;
    }
    std::printf("security_parameters_test: %d check(s) failed\n", g_failures);
    return 1;
}
