/* General PE32/PE64 Software-KSP lifecycle probe. No shield code is loaded.
 * Run only in a disposable prefix clone; init/delete modify named keys.
 * key name is an argument, not a product-specific implementation condition.
 * No CRT, private-key export, forced results, overwrites, or native DLLs.
 */
typedef unsigned long DWORD;
typedef long STATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ ULONG_PTR;
typedef __WCHAR_TYPE__ WCHAR;
#define API __declspec(dllimport) __stdcall
#define SILENT 0x40
#define BAD_KEYSET ((STATUS)0x80090016)
#define EXISTS ((STATUS)0x8009000f)
_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "Windows ABI required");
API WCHAR **CommandLineToArgvW(const WCHAR *, int *);
API const WCHAR *GetCommandLineW(void);
API HANDLE LocalFree(HANDLE);
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
API DWORD GetLastError(void);
__attribute__((noreturn)) API void ExitProcess(DWORD);
API STATUS NCryptOpenStorageProvider(ULONG_PTR *, const WCHAR *, DWORD);
API STATUS NCryptOpenKey(ULONG_PTR, ULONG_PTR *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptCreatePersistedKey(ULONG_PTR, ULONG_PTR *, const WCHAR *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptSetProperty(ULONG_PTR, const WCHAR *, unsigned char *, DWORD, DWORD);
API STATUS NCryptFinalizeKey(ULONG_PTR, DWORD);
API STATUS NCryptExportKey(ULONG_PTR, ULONG_PTR, const WCHAR *, void *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptDeleteKey(ULONG_PTR, DWORD);
API STATUS NCryptFreeObject(ULONG_PTR);
API STATUS NCryptGetProperty(ULONG_PTR, const WCHAR *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptSignHash(ULONG_PTR, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptVerifySignature(ULONG_PTR, void *, unsigned char *, DWORD, unsigned char *, DWORD, DWORD);
API BOOL CryptHashCertificate(ULONG_PTR, DWORD, DWORD, const unsigned char *, DWORD, unsigned char *, DWORD *);

static HANDLE output;
static ULONG_PTR provider, key;
static WCHAR **arguments;
static const char *reference_path;
static unsigned char public_blob[72], public_hash[32];
static DWORD scope;

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

__attribute__((noreturn)) static void finish(DWORD code)
{
    STATUS status;
    if (key)
    {
        status = NCryptFreeObject(key); result("NCryptFreeObject(key)", status);
        if (status && !code) code = 34;
    }
    if (provider)
    {
        status = NCryptFreeObject(provider); result("NCryptFreeObject(provider)", status);
        if (status && !code) code = 35;
    }
    if (arguments) LocalFree(arguments);
    text("probe_exit="); hex(code); text("\r\n");
    CloseHandle(output);
    ExitProcess(code);
}

static BOOL equal(const WCHAR *wide, const char *ascii)
{
    while (*wide && *ascii && *wide == (unsigned char)*ascii) { ++wide; ++ascii; }
    return !*wide && !*ascii;
}

static void api_ok(const char *name, STATUS status, DWORD failure)
{
    result(name, status);
    if (status) finish(failure);
}

static DWORD little32(const unsigned char *p)
{
    return p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static void export_public(void)
{
    DWORD size = 0, hash_size = sizeof(public_hash), i;
    api_ok("NCryptExportKey(ECCPUBLICBLOB,silent)",
           NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_blob,
                           sizeof(public_blob), &size, SILENT), 24);
    text("public_blob_size="); hex(size); text("\r\n");
    if (size != sizeof(public_blob) || little32(public_blob) != 0x31534345 || little32(public_blob+4) != 32)
    {
        text("FAIL: invalid ECDSA P256 public blob shape\r\n"); finish(25);
    }
    if (!CryptHashCertificate(0, 0x800c /* CALG_SHA_256 */, 0, public_blob, size, public_hash, &hash_size) || hash_size != 32)
    {
        text("CryptHashCertificate(public blob) error="); hex(GetLastError()); text("\r\n"); finish(26);
    }
    text("public_blob_sha256=");
    for (i = 0; i < 32; ++i)
    {
        static const char digits[] = "0123456789abcdef";
        char pair[3] = {0, 0, 0};
        pair[0] = digits[public_hash[i] >> 4]; pair[1] = digits[public_hash[i] & 15]; text(pair);
    }
    text("\r\n");
}

static void reference(BOOL save)
{
    HANDLE file;
    unsigned char saved[73];
    DWORD count, i;
    file = CreateFileA(reference_path, save ? 0x40000000 : 0x80000000, 1, 0,
                       save ? 1 /* CREATE_NEW */ : 3 /* OPEN_EXISTING */, 0x80, 0);
    if (file == (HANDLE)-1)
    {
        text("reference_file_error="); hex(GetLastError()); text("\r\n"); finish(27);
    }
    if (save)
    {
        if (!WriteFile(file, public_blob, 72, &count, 0) || count != 72)
        { CloseHandle(file); finish(28); }
    }
    else
    {
        if (!ReadFile(file, saved, sizeof(saved), &count, 0) || count != 72)
        { CloseHandle(file); finish(29); }
        for (i = 0; i < 72; ++i)
            if (saved[i] != public_blob[i]) { CloseHandle(file); finish(30); }
    }
    CloseHandle(file);
    text(save ? "reference_created=1\r\n" : "public_key_matches_previous_process=1\r\n");
}

static void policy_and_signature(void)
{
    unsigned char denied[104], hash[32] = {1}, signature[64];
    DWORD policy = 9, size = 0, i;
    STATUS status;
    api_ok("GetProperty(Export Policy)", NCryptGetProperty(key, L"Export Policy", (unsigned char *)&policy, 4, &size, 0), 40);
    if (size != 4 || policy != 0) finish(41);
    for (i = 0; i < 104; ++i) denied[i] = 0xcc;
    status = NCryptExportKey(key, 0, L"ECCPRIVATEBLOB", 0, denied, 104, &size, SILENT);
    result("ExportKey(private,policy=0)", status);
    if (!status) finish(42);
    for (i = 0; i < 104; ++i) if (denied[i] != 0xcc) finish(43);
    status = NCryptExportKey(key, 0, L"PRIVATEBLOB", 0, denied, 104, &size, 0);
    result("ExportKey(private-alias,policy=0)", status);
    if (!status) finish(44);
    for (i = 0; i < 104; ++i) if (denied[i] != 0xcc) finish(45);
    text("persisted_export_policy_zero=PASS\r\n");
    api_ok("SignHash(reopened-material)", NCryptSignHash(key, 0, hash, 32, signature, 64, &size, SILENT), 46);
    if (size != 64) finish(47);
    api_ok("VerifySignature(reopened-material)", NCryptVerifySignature(key, 0, hash, 32, signature, 64, SILENT), 48);
    hash[0] ^= 1;
    status = NCryptVerifySignature(key, 0, hash, 32, signature, 64, 0);
    result("VerifySignature(altered-digest)", status);
    if (status != (STATUS)0x80090006) finish(49);
    text("persisted_sign_verify=PASS\r\n");
}

void entry(void)
{
    int argc;
    STATUS status;
    DWORD mode, policy = 0;
    ULONG_PTR duplicate = 0;
    output = CreateFileA("cng-probe-result.txt", 0x40000000, 1, 0, 1 /* CREATE_NEW */, 0x80, 0);
    if (output == (HANDLE)-1) ExitProcess(91);
    arguments = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!arguments || argc != 4) { text("usage: probe check|init|reopen|duplicate|delete|absent KEY_NAME user|machine\r\n"); finish(92); }
    if (equal(arguments[3], "user"))
    { scope = 0; reference_path = "C:\\ro-audit-cng\\persist-user.public.bin"; }
    else if (equal(arguments[3], "machine"))
    { scope = 0x20; reference_path = "C:\\ro-audit-cng\\persist-machine.public.bin"; }
    else finish(95);
    if (equal(arguments[1], "check")) mode = 0;
    else if (equal(arguments[1], "init")) mode = 1;
    else if (equal(arguments[1], "reopen")) mode = 2;
    else if (equal(arguments[1], "duplicate")) mode = 3;
    else if (equal(arguments[1], "delete")) mode = 4;
    else if (equal(arguments[1], "absent")) mode = 5;
    else { text("unknown mode\r\n"); finish(93); }
    if (!arguments[2][0]) { text("empty key name refused\r\n"); finish(94); }
    text("Software KSP probe; scope/name from argv; reference is full 72-byte PUBLIC blob.\r\n");
    status = NCryptOpenStorageProvider(&provider, L"Microsoft Software Key Storage Provider", 0);
    result("NCryptOpenStorageProvider(SoftwareKSP,flags=0)", status);
    if (status) { provider = 0; finish(9); }
    if (!provider) { text("FAIL: provider handle is NULL\r\n"); finish(8); }
    status = NCryptOpenKey(provider, &key, arguments[2], 0, SILENT | scope);
    result("NCryptOpenKey(keyspec=0,flags=0x40)", status);
    if (status) key = 0; /* Output is not a valid key handle on failure. */
    if (mode == 5)
    {
        if (status != BAD_KEYSET) finish(11);
        text("missing_key_contract=PASS\r\n"); finish(0);
    }
    if (mode == 1 && status == BAD_KEYSET)
    {
        status = NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", arguments[2], 0, scope);
        result("NCryptCreatePersistedKey(ECDSA_P256,named,flags=0)", status);
        if (status) { key = 0; finish(20); }
        if (!key) { text("FAIL: successful create returned NULL handle\r\n"); finish(12); }
        text("created_key_in_clone=1\r\n");
        api_ok("NCryptSetProperty(Export Policy=0,size=4,flags=0)",
               NCryptSetProperty(key, L"Export Policy", (unsigned char *)&policy, sizeof(policy), 0), 21);
        api_ok("NCryptFinalizeKey(flags=0x40)", NCryptFinalizeKey(key, SILENT), 22);
        export_public(); reference(1); policy_and_signature(); finish(0);
    }
    if (status)
    {
        text("STOP: real OpenKey failure; creation fallback not entered\r\n"); finish(10);
    }
    if (!key) { text("FAIL: successful OpenKey returned NULL handle\r\n"); finish(12); }
    if (mode == 0) { text("open_existing_key_contract=PASS\r\n"); finish(0); }
    if (mode == 1) { text("STOP: init refuses to adopt an already existing named key\r\n"); finish(13); }
    export_public(); reference(0);
    policy_and_signature();
    if (mode == 2) finish(0);
    if (mode == 3)
    {
        status = NCryptCreatePersistedKey(provider, &duplicate, L"ECDSA_P256", arguments[2], 0, scope);
        result("NCryptCreatePersistedKey(existing,same_name,no_overwrite)", status);
        if (!status && duplicate) result("NCryptFreeObject(unexpected_duplicate)", NCryptFreeObject(duplicate));
        if (status != EXISTS) finish(31);
        text("duplicate_name_contract=PASS\r\n"); finish(0);
    }
    /* delete mode verifies the public fingerprint first. Delete consumes handle. */
    api_ok("NCryptDeleteKey(flags=0)", NCryptDeleteKey(key, 0), 32);
    key = 0;
    status = NCryptOpenKey(provider, &key, arguments[2], 0, SILENT | scope);
    result("NCryptOpenKey(after_delete,keyspec=0,flags=0x40)", status);
    if (status) key = 0;
    if (status != BAD_KEYSET) finish(33);
    text("delete_contract=PASS\r\n"); finish(0);
}
