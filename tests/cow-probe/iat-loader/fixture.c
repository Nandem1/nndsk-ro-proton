/* Own DLL: no entry point and no TLS. This exported function is never called.
 * Its only purpose is to give the Windows loader a real USER32.MessageBoxW IAT.
 * The linker places import metadata/IAT in a readable+writable .xsv4 section.
 */
__declspec(dllimport) int __stdcall MessageBoxW(void *, const unsigned short *,
                                              const unsigned short *, unsigned int);
__declspec(dllexport) int import_anchor(void)
{
    return MessageBoxW(0, 0, 0, 0);
}
