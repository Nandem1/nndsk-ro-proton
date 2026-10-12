/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Owned directory only. Captures disk-space lookup with/without a live handle
 * through DOS and the exact GUID path returned by Windows' canonical-path API.
 */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef __WCHAR_TYPE__ WCHAR;
typedef unsigned long long U64;
#define API __declspec(dllimport) __stdcall
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API HANDLE CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API BOOL CreateDirectoryW(const WCHAR *, void *);
API BOOL GetDiskFreeSpaceExW(const WCHAR *, U64 *, U64 *, U64 *);
API DWORD GetFinalPathNameByHandleW(HANDLE, WCHAR *, DWORD, DWORD);
API DWORD GetLastError(void);
API void SetLastError(DWORD);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
API BOOL CloseHandle(HANDLE);
__attribute__((noreturn)) API void ExitProcess(DWORD);
static HANDLE output;
static DWORD failed;
static const WCHAR directory[] = L"C:\\ro-runtime-volume-fixture\\";
static void text(const char *s)
{
    DWORD n=0, written;
    while (s[n]) ++n;
    if (!WriteFile(output, s, n, &written, 0) || written != n) ExitProcess(90);
}
static void hex(DWORD n)
{
    char s[]="0x00000000";
    const char *digits="0123456789abcdef";
    DWORD i;
    for (i=0; i<8; ++i) s[9-i]=digits[(n>>(4*i))&15];
    text(s);
}
static void query(const char *name, const WCHAR *path)
{
    U64 available=0, total=0, free=0;
    BOOL result;
    DWORD error;
    SetLastError(0);
    result=GetDiskFreeSpaceExW(path, &available, &total, &free);
    error=GetLastError();
    text("QUERY name="); text(name); text(" success="); hex(result);
    text(" error="); hex(error); text(" capacityNonzero="); hex(total>0);
    text("\r\n");
    if (!result || !total || !available || free>total || available>total) failed=20;
}
void entry(void)
{
    HANDLE held;
    WCHAR canonical[512];
    DWORD n,i;
    output=CreateFileA("volume-space-result.txt",0x40000000,1,0,1,0x80,0);
    if (output==(HANDLE)-1) ExitProcess(91);
    text("VOLUME_SPACE protocol=1 own_directory_only=1\r\n");
    if (!CreateDirectoryW(directory,0) && GetLastError()!=183) ExitProcess(92);
    query("before-direct",directory);
    held=CreateFileW(directory,0x1000a1,3,0,3,0x2200000,0);
    if (held==(HANDLE)-1) ExitProcess(93);
    n=GetFinalPathNameByHandleW(held,canonical,510,1);
    if (!n || n>=510) ExitProcess(94);
    text("CANONICAL path=");
    for (i=0;i<n;++i) { char c[2]={(char)canonical[i],0}; if (canonical[i]>127) ExitProcess(95); text(c); }
    text("\r\n");
    if (canonical[n-1]!='\\') canonical[n++]='\\';
    canonical[n]=0;
    query("during-direct",directory);
    query("during-guid",canonical);
    if (!CloseHandle(held)) ExitProcess(96);
    query("after-direct",directory);
    query("after-guid",canonical);
    text("probe_exit="); hex(failed); text("\r\n");
    CloseHandle(output);
    ExitProcess(failed);
}
