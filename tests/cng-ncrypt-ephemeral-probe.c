/* PE32/PE64 independent NCrypt ephemeral acceptance probe. Own keys only.
 * Named P256/OpenKey MUST remain unsupported; no protector or persisted data.
 * Allowed private export uses a second own key, in memory only, then wipes it.
 */
typedef unsigned long DWORD;
typedef long STATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ KEY;
typedef __WCHAR_TYPE__ WCHAR;
#define API __declspec(dllimport) __stdcall
#define SILENT 0x40
_Static_assert(sizeof(DWORD) == 4 && sizeof(STATUS) == 4 && sizeof(WCHAR) == 2, "Windows ABI required");
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
__attribute__((noreturn)) API void ExitProcess(DWORD);
API STATUS NCryptOpenStorageProvider(KEY *, const WCHAR *, DWORD);
API STATUS NCryptCreatePersistedKey(KEY, KEY *, const WCHAR *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptSetProperty(KEY, const WCHAR *, unsigned char *, DWORD, DWORD);
API STATUS NCryptGetProperty(KEY, const WCHAR *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptFinalizeKey(KEY, DWORD);
API STATUS NCryptExportKey(KEY, KEY, const WCHAR *, void *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptSignHash(KEY, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptVerifySignature(KEY, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD);
API STATUS NCryptOpenKey(KEY, KEY *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptFreeObject(KEY);
API STATUS BCryptOpenAlgorithmProvider(HANDLE *, const WCHAR *, const WCHAR *, DWORD);
API STATUS BCryptImportKeyPair(HANDLE, HANDLE, const WCHAR *, HANDLE *, unsigned char *, DWORD, DWORD);
API STATUS BCryptVerifySignature(HANDLE, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD);
API STATUS BCryptDestroyKey(HANDLE);
API STATUS BCryptCloseAlgorithmProvider(HANDLE, DWORD);

static HANDLE output, algorithm, verifier;
static KEY provider, key, platform;
static unsigned char private_buffer[104], public_blob[72], signature[64], hash[32] = {1};

static void text(const char *s)
{
    DWORD n = 0, written;
    while (s[n]) ++n;
    if (!WriteFile(output, s, n, &written, 0) || written != n) ExitProcess(90);
}

static void hex(DWORD value)
{
    static const char digits[] = "0123456789abcdef";
    char result[] = "0x00000000";
    DWORD i;
    for (i = 0; i < 8; ++i) result[9-i] = digits[(value >> (4*i)) & 15];
    text(result);
}

static void result(const char *api, STATUS status)
{
    text(api); text(" status="); hex((DWORD)status); text("\r\n");
}

static void wipe_private(void)
{
    volatile unsigned char *buffer = private_buffer;
    DWORD i;
    for (i = 0; i < sizeof(private_buffer); ++i) buffer[i] = 0;
}

__attribute__((noreturn)) static void finish(DWORD code)
{
    STATUS status;
    wipe_private();
    if (verifier) { status = BCryptDestroyKey(verifier); result("BCryptDestroyKey(verifier)", status); if (status && !code) code = 80; }
    if (algorithm) { status = BCryptCloseAlgorithmProvider(algorithm, 0); result("BCryptCloseAlgorithmProvider", status); if (status && !code) code = 81; }
    if (key) { status = NCryptFreeObject(key); result("NCryptFreeObject(key)", status); if (status && !code) code = 82; }
    if (platform) { status = NCryptFreeObject(platform); result("NCryptFreeObject(platform)", status); if (status && !code) code = 83; }
    if (provider) { status = NCryptFreeObject(provider); result("NCryptFreeObject(provider)", status); if (status && !code) code = 84; }
    text("probe_exit="); hex(code); text("\r\n");
    CloseHandle(output);
    ExitProcess(code);
}

static void ok(const char *name, STATUS status, DWORD failure)
{
    result(name, status);
    if (status) finish(failure);
}

static void fail_expected(const char *name, STATUS status, DWORD failure)
{
    result(name, status);
    if (!status) finish(failure);
}

static void drop_key(void)
{
    STATUS status = NCryptFreeObject(key);
    key = 0;
    ok("NCryptFreeObject(completed-cycle)", status, 79);
}

static DWORD little32(const unsigned char *p)
{
    return p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static void unchanged(void)
{
    DWORD i;
    for (i = 0; i < sizeof(private_buffer); ++i) if (private_buffer[i] != 0xcc) finish(78);
}

void entry(void)
{
    STATUS status;
    KEY rejected = 0;
    DWORD policy = 0, value = 0, size, i;
    output = CreateFileA("ncrypt-ephemeral-result.txt", 0x40000000, 1, 0, 1, 0x80, 0);
    if (output == (HANDLE)-1) ExitProcess(91);
    text("General NCrypt ephemeral P256 probe. No named-key success permitted.\r\n");
    status = NCryptOpenStorageProvider(&provider, L"Microsoft Software Key Storage Provider", 0);
    if (status) provider = 0;
    ok("OpenStorageProvider(Software,0)", status, 9);
    if (!provider) finish(8);
    status = NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", 0, 0, 0);
    if (status) key = 0;
    ok("CreatePersistedKey(P256,name=NULL,keyspec=0,flags=0)", status, 10);
    if (!key) finish(11);
    ok("GetProperty(Length)", NCryptGetProperty(key, L"Length", (unsigned char *)&value, sizeof(value), &size, 0), 12);
    if (value != 256 || size != 4) finish(13);
    ok("SetProperty(Export Policy=0)", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&policy, 4, 0), 14);
    fail_expected("SetProperty(short-DWORD)", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&policy, 3, 0), 15);
    value = 255;
    fail_expected("SetProperty(P256,length=255)", NCryptSetProperty(key, L"Length", (unsigned char *)&value, 4, 0), 16);
    ok("GetProperty(Length,after-failed-set)", NCryptGetProperty(key, L"Length", (unsigned char *)&value, 4, &size, 0), 17);
    if (value != 256) finish(18);
    fail_expected("ExportKey(unfinalized)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_blob, 72, &size, 0), 19);
    ok("FinalizeKey(SILENT)", NCryptFinalizeKey(key, SILENT), 20);
    fail_expected("FinalizeKey(repeated)", NCryptFinalizeKey(key, 0), 21);
    ok("ExportKey(public,size-query)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, 0, 0, &size, SILENT), 22);
    if (size != 72) finish(23);
    for (i = 0; i < 104; ++i) private_buffer[i] = 0xcc;
    fail_expected("ExportKey(public,short-buffer)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, private_buffer, 71, &size, 0), 24);
    if (size != 72) finish(25);
    unchanged();
    ok("ExportKey(public,SILENT)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_blob, 72, &size, SILENT), 26);
    if (size != 72 || little32(public_blob) != 0x31534345 || little32(public_blob+4) != 32) finish(27);
    text("public_blob_shape=72/ECS1/32\r\n");
    fail_expected("ExportKey(private,policy=0)", NCryptExportKey(key, 0, L"ECCPRIVATEBLOB", 0, private_buffer, 104, &size, 0), 28);
    unchanged();
    fail_expected("ExportKey(private-alias,policy=0)", NCryptExportKey(key, 0, L"PRIVATEBLOB", 0, private_buffer, 104, &size, 0), 29);
    unchanged();
    fail_expected("ExportKey(opaque,unsupported)", NCryptExportKey(key, 0, L"OpaqueTransport", 0, private_buffer, 104, &size, 0), 30);
    unchanged();
    text("denied_export_buffers_unchanged=PASS\r\n");
    policy = 3;
    fail_expected("SetProperty(post-finalize,subset-unsupported)", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&policy, 4, 0), 31);
    ok("SignHash(P256,SILENT)", NCryptSignHash(key, 0, hash, 32, signature, 64, &size, SILENT), 32);
    if (size != 64) finish(33);
    ok("VerifySignature(NCrypt,SILENT)", NCryptVerifySignature(key, 0, hash, 32, signature, 64, SILENT), 34);
    status = BCryptOpenAlgorithmProvider(&algorithm, L"ECDSA_P256", 0, 0);
    if (status) algorithm = 0;
    ok("BCryptOpenAlgorithmProvider(independent)", status, 35);
    status = BCryptImportKeyPair(algorithm, 0, L"ECCPUBLICBLOB", &verifier, public_blob, 72, 0);
    if (status) verifier = 0;
    ok("BCryptImportKeyPair(public-only)", status, 36);
    ok("BCryptVerifySignature(public-only)", BCryptVerifySignature(verifier, 0, hash, 32, signature, 64, 0), 37);
    hash[0] ^= 1;
    status = NCryptVerifySignature(key, 0, hash, 32, signature, 64, 0);
    result("VerifySignature(NCrypt,altered-digest)", status);
    if (status != (STATUS)0x80090006) finish(38);
    status = BCryptVerifySignature(verifier, 0, hash, 32, signature, 64, 0);
    result("BCryptVerifySignature(altered-digest)", status);
    if (status != (STATUS)0xc000a000) finish(39);
    text("independent_signature_and_negative_control=PASS\r\n");
    drop_key();
    /* A fresh own key proves policy checks are not an unconditional denial. */
    ok("CreatePersistedKey(second-ephemeral)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", 0, 0, 0), 40);
    ok("SetProperty(second-key,policy=3)", NCryptSetProperty(key, L"Export Policy", (unsigned char *)&policy, 4, 0), 41);
    ok("FinalizeKey(second)", NCryptFinalizeKey(key, 0), 42);
    ok("ExportKey(second,allowed-private,in-memory)", NCryptExportKey(key, 0, L"ECCPRIVATEBLOB", 0, private_buffer, 104, &size, 0), 43);
    if (size != 104 || little32(private_buffer) != 0x32534345 || little32(private_buffer+4) != 32) finish(44);
    wipe_private();
    text("allowed_private_export_shape=104/ECS2/32; bytes NOT logged\r\n");
    drop_key();
    ok("CreatePersistedKey(usage-test)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", 0, 0, 0), 45);
    value = 0;
    ok("SetProperty(Key Usage=0)", NCryptSetProperty(key, L"Key Usage", (unsigned char *)&value, 4, 0), 46);
    ok("FinalizeKey(usage-test)", NCryptFinalizeKey(key, 0), 47);
    fail_expected("SignHash(usage=0,denied)", NCryptSignHash(key, 0, hash, 32, signature, 64, &size, 0), 48);
    drop_key();
    status = NCryptCreatePersistedKey(provider, &rejected, L"ECDSA_P256", L"Wine.EphemeralProbe.NoPersist", 0, 0);
    result("CreatePersistedKey(named,still-unsupported)", status);
    if (!status && rejected) { NCryptFreeObject(rejected); finish(49); }
    if (status != (STATUS)0x80090029) finish(50);
    status = NCryptOpenKey(provider, &rejected, L"Wine.EphemeralProbe.NoPersist", 0, SILENT);
    result("OpenKey(still-unsupported)", status);
    if (!status && rejected) { NCryptFreeObject(rejected); finish(51); }
    if (status != (STATUS)0x80090029) finish(52);
    /* The old OpenStorageProvider stub is NOT a TPM implementation. */
    status = NCryptOpenStorageProvider(&platform, L"Microsoft Platform Crypto Provider", 0);
    result("OpenStorageProvider(Platform,legacy-stub)", status);
    if (!status && platform)
    {
        status = NCryptCreatePersistedKey(platform, &rejected, L"ECDSA_P256", 0, 0, 0);
        result("CreatePersistedKey(Platform,must-NOT-use-software)", status);
        if (!status && rejected) { NCryptFreeObject(rejected); finish(53); }
        if (status != (STATUS)0x80090029) finish(54);
    }
    else platform = 0;
    text("no_persisted_key_success=PASS\r\nno_TPM_software_substitution=PASS\r\n");
    for (i = 0; i < 3; ++i)
    {
        ok("CreatePersistedKey(repeat-cycle)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", 0, 0, 0), 55);
        ok("FinalizeKey(repeat-cycle)", NCryptFinalizeKey(key, 0), 56);
        drop_key();
    }
    text("repeat_cycles=PASS\r\nephemeral_p256=PASS\r\n");
    finish(0);
}
