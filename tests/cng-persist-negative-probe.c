/* Wine storage fault fixtures: only own named keys in an isolated test prefix.
 * Corrupt/restore a PROTECTED value, never export/decrypt/log private material.
 */
typedef unsigned long DWORD;
typedef long STATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ KEY;
typedef __WCHAR_TYPE__ WCHAR;
#define API __declspec(dllimport) __stdcall
_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "Windows ABI required");
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
__attribute__((noreturn)) API void ExitProcess(DWORD);
API STATUS NCryptOpenStorageProvider(KEY *, const WCHAR *, DWORD);
API STATUS NCryptCreatePersistedKey(KEY, KEY *, const WCHAR *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptFinalizeKey(KEY, DWORD);
API STATUS NCryptOpenKey(KEY, KEY *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptExportKey(KEY, KEY, const WCHAR *, void *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptGetProperty(KEY, const WCHAR *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptFreeObject(KEY);
API STATUS NCryptDeleteKey(KEY, DWORD);
API STATUS RegOpenKeyExW(HANDLE, const WCHAR *, DWORD, DWORD, HANDLE *);
API STATUS RegQueryValueExW(HANDLE, const WCHAR *, DWORD *, DWORD *, unsigned char *, DWORD *);
API STATUS RegSetValueExW(HANDLE, const WCHAR *, DWORD, DWORD, const unsigned char *, DWORD);
API STATUS RegFlushKey(HANDLE);
API STATUS RegCloseKey(HANDLE);

static HANDLE output, registry;
static KEY provider, key, platform;
static const WCHAR name[] = L"Wine.CngPersist.FaultFixture";
static const WCHAR path[] = L"Software\\Wine\\Crypto\\CNG\\SoftwareKSP\\Keys";
static unsigned char protected[65536], changed[65536], public_before[72], public_after[72], oversized[65537];
static DWORD protected_size;
static BOOL modified;

static void text(const char *s)
{
    DWORD n = 0, written;
    while (s[n]) ++n;
    if (!WriteFile(output, s, n, &written, 0) || written != n) ExitProcess(90);
}
static void hex(DWORD v)
{
    const char digits[] = "0123456789abcdef";
    char b[] = "0x00000000";
    DWORD i;
    for (i = 0; i < 8; ++i) b[9-i] = digits[(v >> (i*4)) & 15];
    text(b);
}
static void result(const char *s, STATUS v)
{ text(s); text(" status="); hex((DWORD)v); text("\r\n"); }
static STATUS restore(void)
{
    STATUS r = RegSetValueExW(registry, name, 0, 3, protected, protected_size);
    if (!r) r = RegFlushKey(registry);
    if (!r) modified = 0;
    return r;
}
__attribute__((noreturn)) static void finish(DWORD code)
{
    if (modified) { result("Restore(failure-cleanup)", restore()); }
    if (key) result("FreeObject(key)", NCryptFreeObject(key));
    if (platform) result("FreeObject(platform)", NCryptFreeObject(platform));
    if (provider) result("FreeObject(provider)", NCryptFreeObject(provider));
    if (registry) result("RegCloseKey", RegCloseKey(registry));
    text("probe_exit="); hex(code); text("\r\n");
    CloseHandle(output); ExitProcess(code);
}
static void ok(const char *s, STATUS v, DWORD code)
{ result(s, v); if (v) finish(code); }
static void expected(const char *s, STATUS v, STATUS wanted, DWORD code)
{ result(s, v); if (v != wanted) finish(code); }
static void corrupt(unsigned char *data, DWORD count, DWORD type)
{
    ok("RegSetValue(fault-fixture)", RegSetValueExW(registry, name, 0, type, data, count), 50);
    modified = 1;
    ok("RegFlushKey(fault-fixture)", RegFlushKey(registry), 51);
    expected("OpenKey(corrupt,not-missing)", NCryptOpenKey(provider, &key, name, 0, 0x40), (STATUS)0x80090005, 52);
    key = 0;
    expected("CreateKey(corrupt,not-regenerated)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", name, 0, 0), (STATUS)0x8009000f, 53);
    key = 0;
    ok("Restore(protected-original)", restore(), 54);
}

void entry(void)
{
    DWORD size, type, i, property;
    output = CreateFileA("cng-negative-result.txt", 0x40000000, 1, 0, 1, 0x80, 0);
    if (output == (HANDLE)-1) ExitProcess(91);
    ok("OpenStorageProvider(Software)", NCryptOpenStorageProvider(&provider, L"Microsoft Software Key Storage Provider", 0), 1);
    expected("OpenKey(own-fixture,missing)", NCryptOpenKey(provider, &key, name, 0, 0), (STATUS)0x80090016, 2);
    key = 0;
    ok("CreateKey(own-fixture)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", name, 0, 0), 3);
    ok("Finalize(own-fixture)", NCryptFinalizeKey(key, 0), 4);
    ok("ExportPublic(own-fixture)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_before, 72, &size, 0), 5);
    if (size != 72) finish(6);
    ok("Free(own-fixture)", NCryptFreeObject(key), 7); key = 0;
    ok("RegOpenKey(own-store)", RegOpenKeyExW((HANDLE)(__INTPTR_TYPE__)(int)0x80000001, path, 0, 0x103, &registry), 8);
    protected_size = sizeof(protected);
    ok("RegQueryValue(protected-fixture)", RegQueryValueExW(registry, name, 0, &type, protected, &protected_size), 9);
    if (type != 3 || !protected_size || protected_size >= sizeof(protected)) finish(10);
    /* Break ciphertext, then restore its original bytes before checking identity. */
    protected[protected_size - 1] ^= 1;
    for (i = 0; i < protected_size; ++i) changed[i] = protected[i];
    protected[protected_size - 1] ^= 1;
    corrupt(changed, protected_size, 3);
    changed[0] = changed[1] = 0;
    corrupt(changed, 2, 1); /* Wrong registry type. */
    corrupt(oversized, sizeof(oversized), 3); /* Bounded parser before allocation. */
    expected("OpenKey(bad-flags)", NCryptOpenKey(provider, &key, name, 0, 0x80000000), (STATUS)0x80090009, 11);
    key = 0;
    expected("CreateKey(bad-flags)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", name, 0, 1), (STATUS)0x80090009, 12);
    key = 0;
    expected("Named-RSA(must-not-fake-persistence)", NCryptCreatePersistedKey(provider, &key, L"RSA", L"Wine.CngPersist.UnsupportedRSA", 0, 0), (STATUS)0x80090029, 25);
    key = 0;
    expected("OpenKey(legacy-keyspec,unsupported)", NCryptOpenKey(provider, &key, name, 2, 0), (STATUS)0x80090029, 13);
    key = 0;
    ok("OpenStorageProvider(Platform,old-stub)", NCryptOpenStorageProvider(&platform, L"Microsoft Platform Crypto Provider", 0), 14);
    expected("Platform-cannot-open-software-key", NCryptOpenKey(platform, &key, name, 0, 0), (STATUS)0x80090029, 15);
    key = 0;
    expected("Platform-cannot-create-software-key", NCryptCreatePersistedKey(platform, &key, L"ECDSA_P256", 0, 0, 0), (STATUS)0x80090029, 16);
    key = 0;
    ok("OpenKey(restored-own-fixture)", NCryptOpenKey(provider, &key, name, 0, 0), 17);
    ok("ExportPublic(restored)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_after, 72, &size, 0), 18);
    if (size != 72) finish(19);
    for (i = 0; i < 72; ++i) if (public_before[i] != public_after[i]) finish(20);
    property = 9;
    ok("GetProperty(restored-policy)", NCryptGetProperty(key, L"Export Policy", (unsigned char *)&property, 4, &size, 0), 21);
    if (size != 4 || property != 0) finish(22);
    text("corruption_never_became_missing_or_regenerated=PASS\r\nrestored_public_and_policy=PASS\r\nno_TPM_substitution=PASS\r\n");
    ok("DeleteKey(own-fixture)", NCryptDeleteKey(key, 0), 23); key = 0;
    expected("OpenKey(after-fixture-delete)", NCryptOpenKey(provider, &key, name, 0, 0), (STATUS)0x80090016, 24);
    key = 0;
    finish(0);
}
