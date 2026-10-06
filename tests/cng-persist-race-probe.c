/* Two real processes configure the same OWN key before an event barrier.
 * Exactly one Finalize must publish; the other must return NTE_EXISTS.
 * Parent reopens the winner, compares full PUBLIC bytes, then deletes it.
 */
typedef unsigned long DWORD;
typedef long STATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ KEY;
typedef __WCHAR_TYPE__ WCHAR;
typedef unsigned short WORD;
#define API __declspec(dllimport) __stdcall
_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "Windows ABI required");
struct startup {
    DWORD cb; WCHAR *reserved, *desktop, *title;
    DWORD x, y, cx, cy, chars_x, chars_y, fill, flags;
    WORD show, reserved_size; unsigned char *reserved_data;
    HANDLE in, out, err;
};
struct process_info { HANDLE process, thread; DWORD pid, tid; };
_Static_assert(sizeof(struct startup) == (sizeof(void *) == 8 ? 104 : 68), "STARTUPINFO ABI");
_Static_assert(sizeof(struct process_info) == (sizeof(void *) == 8 ? 24 : 16), "PROCESS_INFORMATION ABI");
API WCHAR **CommandLineToArgvW(const WCHAR *, int *);
API const WCHAR *GetCommandLineW(void);
API HANDLE LocalFree(HANDLE);
API BOOL CreateProcessW(const WCHAR *, WCHAR *, void *, void *, BOOL, DWORD, void *, const WCHAR *, struct startup *, struct process_info *);
API HANDLE CreateEventW(void *, BOOL, BOOL, const WCHAR *);
API BOOL SetEvent(HANDLE);
API DWORD WaitForMultipleObjects(DWORD, const HANDLE *, BOOL, DWORD);
API DWORD WaitForSingleObject(HANDLE, DWORD);
API BOOL GetExitCodeProcess(HANDLE, DWORD *);
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
__attribute__((noreturn)) API void ExitProcess(DWORD);
API STATUS NCryptOpenStorageProvider(KEY *, const WCHAR *, DWORD);
API STATUS NCryptCreatePersistedKey(KEY, KEY *, const WCHAR *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptFinalizeKey(KEY, DWORD);
API STATUS NCryptOpenKey(KEY, KEY *, const WCHAR *, DWORD, DWORD);
API STATUS NCryptExportKey(KEY, KEY, const WCHAR *, void *, unsigned char *, DWORD, DWORD *, DWORD);
API STATUS NCryptFreeObject(KEY);
API STATUS NCryptDeleteKey(KEY, DWORD);

static const WCHAR key_name[] = L"Wine.CngPersist.RaceFixture";
static const WCHAR ready1_name[] = L"Local\\Wine.CngPersist.Race.Ready1";
static const WCHAR ready2_name[] = L"Local\\Wine.CngPersist.Race.Ready2";
static const WCHAR go_name[] = L"Local\\Wine.CngPersist.Race.Go";
static HANDLE output, ready[2], go, children[2];
static KEY provider, key;
static WCHAR **argv;

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
__attribute__((noreturn)) static void finish(DWORD code)
{
    DWORD i;
    if (key) result("FreeObject(key)", NCryptFreeObject(key));
    if (provider) result("FreeObject(provider)", NCryptFreeObject(provider));
    for (i = 0; i < 2; ++i) { if (ready[i]) CloseHandle(ready[i]); if (children[i]) CloseHandle(children[i]); }
    if (go) CloseHandle(go);
    if (argv) LocalFree(argv);
    text("probe_exit="); hex(code); text("\r\n");
    CloseHandle(output); ExitProcess(code);
}
static void ok(const char *s, STATUS v, DWORD code)
{ result(s, v); if (v) finish(code); }
static BOOL equals(const WCHAR *s, const char *v)
{
    while (*s && *v && *s == (unsigned char)*v) { ++s; ++v; }
    return !*s && !*v;
}

void entry(void)
{
    int argc;
    DWORD worker = 0, size, count, exits[2], i;
    STATUS status;
    struct startup si = {0};
    struct process_info pi;
    unsigned char public_blob[72], reference[73];
    HANDLE file;
    WCHAR command1[] = L"probe worker1", command2[] = L"probe worker2";
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc == 2)
    { if (equals(argv[1], "worker1")) worker = 1; else if (equals(argv[1], "worker2")) worker = 2; }
    output = CreateFileA(worker == 1 ? "race-worker1.txt" : worker == 2 ? "race-worker2.txt" : "cng-race-result.txt", 0x40000000, 1, 0, 1, 0x80, 0);
    if (output == (HANDLE)-1) ExitProcess(91);
    if (!argv || argc != 2) finish(92);
    ready[0] = CreateEventW(0, 1, 0, ready1_name);
    ready[1] = CreateEventW(0, 1, 0, ready2_name);
    go = CreateEventW(0, 1, 0, go_name);
    if (!ready[0] || !ready[1] || !go) finish(1);
    ok("OpenStorageProvider(Software)", NCryptOpenStorageProvider(&provider, L"Microsoft Software Key Storage Provider", 0), 2);
    if (worker)
    {
        ok("CreateKey(before-barrier)", NCryptCreatePersistedKey(provider, &key, L"ECDSA_P256", key_name, 0, 0), 3);
        if (!SetEvent(ready[worker-1])) finish(4);
        if (WaitForSingleObject(go, 12000) != 0) finish(5);
        status = NCryptFinalizeKey(key, 0);
        result("FinalizeKey(after-barrier)", status);
        if (status == (STATUS)0x8009000f) finish(15); /* Expected losing publisher. */
        if (status) finish(6);
        ok("ExportPublic(winner)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_blob, 72, &size, 0), 7);
        if (size != 72) finish(8);
        file = CreateFileA("race-winner.public.bin", 0x40000000, 1, 0, 1, 0x80, 0);
        if (file == (HANDLE)-1) finish(9);
        if (!WriteFile(file, public_blob, 72, &count, 0) || count != 72) { CloseHandle(file); finish(10); }
        CloseHandle(file);
        finish(0);
    }
    status = NCryptOpenKey(provider, &key, key_name, 0, 0);
    result("OpenKey(own-race-fixture,missing)", status);
    if (status != (STATUS)0x80090016) finish(16);
    key = 0;
    si.cb = sizeof(si);
    if (!CreateProcessW(argv[1], command1, 0, 0, 0, 0, 0, 0, &si, &pi)) finish(17);
    children[0] = pi.process; CloseHandle(pi.thread);
    if (!CreateProcessW(argv[1], command2, 0, 0, 0, 0, 0, 0, &si, &pi)) finish(18);
    children[1] = pi.process; CloseHandle(pi.thread);
    if (WaitForMultipleObjects(2, ready, 1, 12000) != 0) finish(19);
    text("both_processes_configured_before_publish=PASS\r\n");
    if (!SetEvent(go)) finish(20);
    if (WaitForMultipleObjects(2, children, 1, 20000) != 0) finish(21);
    if (!GetExitCodeProcess(children[0], exits) || !GetExitCodeProcess(children[1], exits+1)) finish(22);
    text("child1_exit="); hex(exits[0]); text("\r\nchild2_exit="); hex(exits[1]); text("\r\n");
    if (!((exits[0] == 0 && exits[1] == 15) || (exits[0] == 15 && exits[1] == 0))) finish(23);
    ok("OpenKey(winner)", NCryptOpenKey(provider, &key, key_name, 0, 0), 24);
    ok("ExportPublic(reopened-winner)", NCryptExportKey(key, 0, L"ECCPUBLICBLOB", 0, public_blob, 72, &size, 0), 25);
    if (size != 72) finish(26);
    file = CreateFileA("race-winner.public.bin", 0x80000000, 1, 0, 3, 0x80, 0);
    if (file == (HANDLE)-1) finish(27);
    if (!ReadFile(file, reference, 73, &count, 0) || count != 72) { CloseHandle(file); finish(28); }
    CloseHandle(file);
    for (i = 0; i < 72; ++i) if (reference[i] != public_blob[i]) finish(29);
    text("single_publisher_and_winner_public_key=PASS\r\n");
    ok("DeleteKey(own-race-fixture)", NCryptDeleteKey(key, 0), 30); key = 0;
    status = NCryptOpenKey(provider, &key, key_name, 0, 0);
    result("OpenKey(after-race-delete)", status);
    if (status != (STATUS)0x80090016) finish(31);
    key = 0;
    finish(0);
}
