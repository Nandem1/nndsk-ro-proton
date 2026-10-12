/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only Wine API query. No prefix, registry, client or security-policy writes.
 */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef __WCHAR_TYPE__ WCHAR;
#define API __declspec(dllimport) __stdcall
_Static_assert(sizeof(DWORD)==4 && sizeof(WCHAR)==2, "Windows ABI required");
API BOOL GetVolumeNameForVolumeMountPointW(const WCHAR *, WCHAR *, DWORD);
API HANDLE GetStdHandle(DWORD);
API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__attribute__((noreturn)) API void ExitProcess(DWORD);
void entry(void)
{
    WCHAR volume[50];
    static char output[80]="NNDSK_C_VOLUME_V1 ";
    DWORD i=0,n=sizeof("NNDSK_C_VOLUME_V1 ")-1,written;
    if (!GetVolumeNameForVolumeMountPointW(L"C:\\",volume,50)) ExitProcess(10);
    while (volume[i])
    {
        if (i>=49 || volume[i]>127) ExitProcess(11);
        output[n++]=(char)volume[i++];
    }
    output[n++]='\n';
    if (!WriteFile(GetStdHandle((DWORD)-11),output,n,&written,0) || written!=n) ExitProcess(12);
    ExitProcess(0);
}
