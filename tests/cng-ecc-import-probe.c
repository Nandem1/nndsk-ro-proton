/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Owned public-key fixture. No private key, client, protection or registry access.
 * Reproduces the named-curve NCrypt import used by .NET ECDsaCng.
 */
typedef unsigned long DWORD;
typedef long STATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ KEY;
typedef __WCHAR_TYPE__ WCHAR;
#define API __declspec(dllimport) __stdcall
#define INVALID_PARAMETER ((STATUS)0x80090027)
#define NOT_SUPPORTED ((STATUS)0x80090029)
#define BAD_SIGNATURE ((STATUS)0x80090006)
#define BAD_FLAGS ((STATUS)0x80090009)
#define INVALID_HANDLE ((STATUS)0x80090026)
#define BUFFER_TOO_SMALL ((STATUS)0x80090028)
_Static_assert(sizeof(DWORD) == 4 && sizeof(STATUS) == 4 && sizeof(WCHAR) == 2, "Windows ABI required");
typedef struct { DWORD bytes, type; void *value; } BUFFER;
typedef struct { DWORD version, count; BUFFER *buffers; } PARAMETERS;
_Static_assert(sizeof(PARAMETERS) == (sizeof(KEY) == 8 ? 16 : 12), "NCryptBufferDesc ABI");
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
__attribute__((noreturn)) API void ExitProcess(DWORD);
API STATUS NCryptOpenStorageProvider(KEY *, const WCHAR *, DWORD);
API STATUS NCryptImportKey(KEY, KEY, const WCHAR *, PARAMETERS *, KEY *, unsigned char *, DWORD, DWORD);
API STATUS NCryptGetProperty(KEY, const WCHAR *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptSetProperty(KEY, const WCHAR *, unsigned char *, DWORD, DWORD);
API STATUS NCryptExportKey(KEY, KEY, const WCHAR *, PARAMETERS *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptVerifySignature(KEY, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD);
API STATUS NCryptSignHash(KEY, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptFreeObject(KEY);

static HANDLE output;
static KEY provider, key;
static unsigned char public_blob[72] = {
    0x45,0x43,0x44,0x50, 32,0,0,0,
    0xae,0x34,0x4d,0x3e,0x42,0xf7,0xa7,0xe6,0x46,0x9f,0x71,0xf2,0x0d,0xe0,0xea,0x5e,
    0xb3,0x05,0xb3,0x32,0x07,0x6e,0xdf,0x15,0xe9,0xd6,0xfd,0x64,0x9e,0xe9,0x83,0xfd,
    0x7c,0x8f,0xe3,0xbc,0xc3,0x21,0x1f,0xa1,0x2e,0x27,0xd7,0xa4,0x20,0x8c,0xc5,0xaf,
    0x74,0x75,0x62,0x9b,0xff,0xf7,0xa7,0x23,0x55,0x7e,0x2a,0xb2,0xcd,0x83,0x91,0x61,
};
static unsigned char signature[64] = {
    0x57,0x76,0xa3,0xd5,0xdb,0x00,0xcd,0xa9,0xf4,0x48,0xe6,0xf4,0x2b,0x59,0x58,0xc5,
    0xa3,0xea,0xc9,0x25,0x06,0xbb,0x79,0x1b,0xc3,0x49,0xa8,0xc8,0xb2,0xa4,0x0d,0xe2,
    0xdf,0x24,0x54,0xea,0x82,0xf5,0x34,0x27,0xde,0x60,0xf7,0xa7,0x11,0xbe,0xf8,0xd0,
    0xea,0x8e,0xe1,0x1e,0xa4,0xa1,0x84,0x2c,0x43,0x98,0xe4,0x47,0x10,0xdb,0x59,0x5d,
};
static unsigned char digest[32] = {
    0x97,0x93,0x05,0xf0,0x40,0x78,0x66,0x8b,0xd3,0xcf,0x66,0xa5,0xdc,0x40,0xb1,0x89,
    0x18,0xa3,0x67,0x4d,0xe8,0xed,0x58,0xc8,0xae,0xf9,0xfb,0xea,0x4b,0xe7,0x9b,0xdb,
};
static WCHAR curve[] = L"nistP256";
static BUFFER buffer = {sizeof(curve), 60, curve};
static PARAMETERS parameters = {0, 1, &buffer};

static void text(const char *s)
{
    DWORD size = 0, written;
    while (s[size]) ++size;
    if (!WriteFile(output, s, size, &written, 0) || written != size) ExitProcess(90);
}
static void hex(DWORD value)
{
    static const char digits[] = "0123456789abcdef";
    char result[] = "0x00000000";
    DWORD i;
    for (i = 0; i < 8; ++i) result[9-i] = digits[(value >> (4*i)) & 15];
    text(result);
}
__attribute__((noreturn)) static void finish(DWORD code)
{
    if (key && NCryptFreeObject(key) && !code) code = 80;
    if (provider && NCryptFreeObject(provider) && !code) code = 81;
    text("probe_exit="); hex(code); text("\r\n");
    CloseHandle(output);
    ExitProcess(code);
}
static void expect(const char *name, STATUS actual, STATUS expected)
{
    text("CASE name="); text(name); text(" status="); hex((DWORD)actual);
    text(" expected="); hex((DWORD)expected); text("\r\n");
    if (actual != expected) { text("FAIL\r\n"); finish(10); }
}
static void property(const WCHAR *name, const WCHAR *expected, DWORD expected_size)
{
    unsigned char bytes[64];
    DWORD size, i;
    expect("property-size", NCryptGetProperty(key, name, 0, 0, &size, 0), 0);
    if (size != expected_size || size > sizeof(bytes)) finish(11);
    expect("property-value", NCryptGetProperty(key, name, bytes, sizeof(bytes), &size, 0), 0);
    for (i = 0; i < size; ++i) if (bytes[i] != ((const unsigned char *)expected)[i]) finish(12);
}
static void reject(const char *name, PARAMETERS *params, unsigned char *blob, DWORD size, DWORD flags, STATUS status)
{
    KEY rejected = 0;
    STATUS result = NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", params, &rejected, blob, size, flags);
    expect(name, result, status);
    if (rejected) { NCryptFreeObject(rejected); finish(13); }
}
static void drop_key(void)
{
    expect("free-imported-key", NCryptFreeObject(key), 0);
    key = 0;
}
void entry(void)
{
    unsigned char exported[104];
    DWORD size, length, i;
    WCHAR other[] = L"nistP384";
    BUFFER bad_buffer = buffer, duplicates[2] = {buffer, buffer};
    PARAMETERS bad = parameters, empty = {0,0,0};
    STATUS status;
    unsigned char ephemeral = 1;
    DWORD export_policy = 2;
    DWORD unsupported_policy = 4;
    output = CreateFileA("cng-ecc-import-result.txt", 0x40000000, 1, 0, 1, 0x80, 0);
    if (output == (HANDLE)-1) ExitProcess(91);
    text("CNG_ECC_IMPORT protocol=1 own_public_fixture_only=1 curve=nistP256 bytes=72\r\n");
    expect("open-software-ksp", NCryptOpenStorageProvider(&provider, L"Microsoft Software Key Storage Provider", 0), 0);
    status = NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", &parameters, &key, public_blob, 72, 0);
    expect("dotnet-named-generic-import", status, 0);
    if (!key) finish(14);
    expect("length", NCryptGetProperty(key, L"Length", (unsigned char *)&length, 4, &size, 0), 0);
    if (length != 256 || size != 4) finish(15);
    property(L"Algorithm Group", L"ECDSA", sizeof(L"ECDSA"));
    property(L"ECCCurveName", curve, sizeof(curve));
    property(L"Algorithm Name", L"ECDSA_P256", sizeof(L"ECDSA_P256"));
    expect("dotnet-ephemeral-set", NCryptSetProperty(key, L"CLR IsEphemeral", &ephemeral, 1, 0x40000000), 0);
    ephemeral = 0;
    expect("dotnet-ephemeral-get", NCryptGetProperty(key, L"CLR IsEphemeral", &ephemeral, 1, &size, 0x40000000), 0);
    if (ephemeral != 1 || size != 1) finish(21);
    expect("dotnet-export-policy", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&export_policy, 4, 0x80000000), 0);
    expect("ephemeral-export-policy-no-persist", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&export_policy, 4, 0), 0);
    expect("export-policy-mixed-flags", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&export_policy, 4, 0xc0000000), BAD_FLAGS);
    expect("persist-unrelated-property-denied", NCryptSetProperty(key, L"Length", (unsigned char *)&length, 4, 0x80000000), BAD_FLAGS);
    expect("unsupported-export-policy", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&unsupported_policy, 4, 0x80000000), NOT_SUPPORTED);
    export_policy = 0;
    expect("export-policy-unchanged-after-error", NCryptGetProperty(key, L"Export Policy", (unsigned char *)&export_policy, 4, &size, 0), 0);
    if (export_policy != 2 || size != 4) finish(22);
    expect("public-private-export-denied", NCryptExportKey(key, 0, L"ECCPRIVATEBLOB", 0, 0, 0, &size, 0), (STATUS)0x80090010);
    ephemeral = 2;
    expect("invalid-ephemeral-value", NCryptSetProperty(key, L"CLR IsEphemeral", &ephemeral, 1, 0x40000000), INVALID_PARAMETER);
    ephemeral = 1;
    expect("invalid-ephemeral-flags", NCryptSetProperty(key, L"CLR IsEphemeral", &ephemeral, 1, 0), BAD_FLAGS);
    expect("verify-valid", NCryptVerifySignature(key, 0, digest, 32, signature, 64, 0), 0);
    signature[0] ^= 1;
    expect("verify-altered-signature", NCryptVerifySignature(key, 0, digest, 32, signature, 64, 0), BAD_SIGNATURE);
    signature[0] ^= 1;
    digest[0] ^= 1;
    expect("verify-altered-digest", NCryptVerifySignature(key, 0, digest, 32, signature, 64, 0), BAD_SIGNATURE);
    digest[0] ^= 1;
    expect("export-size", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, 0, 0, &size, 0), 0);
    if (size != 72) finish(16);
    for (i = 0; i < sizeof(exported); ++i) exported[i] = 0xcc;
    expect("export-short", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, exported, 71, &size, 0), BUFFER_TOO_SMALL);
    for (i = 0; i < sizeof(exported); ++i) if (exported[i] != 0xcc) finish(17);
    expect("export-public", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, exported, 72, &size, 0), 0);
    if (size != 72 || exported[4] != 32) finish(18);
    for (i = 8; i < 72; ++i) if (exported[i] != public_blob[i]) finish(19);
    status = NCryptSignHash(key, 0, digest, 32, exported, 64, &size, 0);
    text("public-sign-denied status="); hex((DWORD)status); text("\r\n");
    if (!status) finish(20);
    drop_key();
    reject("generic-needs-curve", 0, public_blob, 72, 0, INVALID_PARAMETER);
    reject("short-blob", &parameters, public_blob, 71, 0, INVALID_PARAMETER);
    reject("extra-blob-byte", &parameters, exported, 73, 0, INVALID_PARAMETER);
    public_blob[4] = 48;
    reject("wrong-coordinate-size", &parameters, public_blob, 72, 0, INVALID_PARAMETER);
    public_blob[4] = 32;
    reject("null-blob", &parameters, 0, 72, 0, INVALID_PARAMETER);
    reject("bad-flags", &parameters, public_blob, 72, 1, BAD_FLAGS);
    bad_buffer.type = 999; bad.buffers = &bad_buffer;
    reject("unknown-parameter", &bad, public_blob, 72, 0, NOT_SUPPORTED);
    bad_buffer = buffer; bad_buffer.bytes = 17;
    reject("odd-curve-bytes", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    bad_buffer = buffer; bad_buffer.value = 0;
    reject("null-curve", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    bad_buffer = buffer; curve[8] = L'x';
    reject("unterminated-curve", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    curve[8] = 0;
    bad_buffer = buffer; bad_buffer.value = other;
    reject("unsupported-curve", &bad, public_blob, 72, 0, NOT_SUPPORTED);
    bad = parameters; bad.version = 1;
    reject("descriptor-version", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    bad = parameters; bad.count = 2; bad.buffers = duplicates;
    reject("duplicate-curve", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    bad = parameters; bad.buffers = 0;
    reject("null-buffer-list", &bad, public_blob, 72, 0, INVALID_PARAMETER);
    expect("null-provider", NCryptImportKey(0, 0, L"ECCPUBLICBLOB", &parameters, &key, public_blob, 72, 0), INVALID_HANDLE);
    expect("null-handle-output", NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", &parameters, 0, public_blob, 72, 0), INVALID_PARAMETER);
    public_blob[2] = 0x53; public_blob[3] = 0x31;
    expect("fixed-p256-no-parameters", NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", 0, &key, public_blob, 72, 0), 0);
    expect("fixed-verify", NCryptVerifySignature(key, 0, digest, 32, signature, 64, 0), 0);
    drop_key();
    expect("fixed-empty-parameters", NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", &empty, &key, public_blob, 72, 0), 0);
    drop_key();
    public_blob[2] = 0x44; public_blob[3] = 0x50;
    for (i = 0; i < 32; ++i)
    {
        expect("repeat-import", NCryptImportKey(provider, 0, L"ECCPUBLICBLOB", &parameters, &key, public_blob, 72, 0x40), 0);
        expect("repeat-verify", NCryptVerifySignature(key, 0, digest, 32, signature, 64, 0x40), 0);
        drop_key();
    }
    text("roundtrip_and_signature_controls=PASS repeated_cycles=32\r\n");
    finish(0);
}
