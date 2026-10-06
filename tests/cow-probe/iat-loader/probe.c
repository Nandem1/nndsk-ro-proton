/* Reuse checked PE32 ABI and output/query helpers, not the old experiment.
 * map_probe_entry is unreferenced and removed by /opt:ref. No original files
 * change. The entry below maps and loads ONLY our own inert fixture.
 */
#define entry map_probe_entry
#include "../probe.c"
#undef entry

API HANDLE LoadLibraryW(const WORD *);
API BOOL FreeLibrary(HANDLE);
static const WORD ownFixture[] = {
    'i','a','t','-','f','i','x','t','u','r','e','.','d','l','l',0
};
static const WORD user32Name[] = {'u','s','e','r','3','2','.','d','l','l',0};

static BOOL ascii_equal(const BYTE *base, DWORD offset, DWORD limit, const char *s)
{
    DWORD i=0;
    while(s[i]) {
        if(offset+i>=limit || base[offset+i]!=(BYTE)s[i]) return 0;
        ++i;
    }
    return offset+i<limit && !base[offset+i];
}

void entry(void)
{
    DWORD length,i,directoryEnd=0,pe,optional,sectionTable,sections;
    DWORD imageSize,imports,ilt,iat,at,sectionFlags=0,entryRva,tlsRva;
    DWORD diskSize,sizeHigh=0,rawBefore,rawAfter,loadedValue,expectedValue;
    DWORD count;
    HANDLE loaded=0;
    BYTE *image;
    MBI32 mappedBefore,mappedAfter,loadedInfo;
    SYSTEM_INFO32 system={0};
    VERSION32 version={0};
    long (__stdcall *rtlGetVersion)(VERSION32 *);
    output=CreateFileA("iat-probe-result.txt",0x40000000,1,0,1,0x80,0);
    if(output==INVALID_HANDLE) {
        const char msg[]="Refusing to overwrite iat-probe-result.txt.\r\n";
        HANDLE standard=GetStdHandle((DWORD)-11);
        if(standard && standard!=INVALID_HANDLE) raw(standard,msg,sizeof(msg)-1);
        ExitProcess(2);
    }
    text("IAT_PROBE protocol=1 arch=PE32 fixture=iat-fixture.dll own_fixture_only=1 no_manual_write=1 no_VirtualProtect=1\r\n");
    GetNativeSystemInfo(&system);
    text("SYSTEM");field("NativeArchitecture",system.architecture);field("PageSize",system.pageSize);
    field("AllocationGranularity",system.allocationGranularity);field("Pid",GetCurrentProcessId());text("\r\n");
    rtlGetVersion=(long (__stdcall *)(VERSION32 *))GetProcAddress(GetModuleHandleW(ntdllName),"RtlGetVersion");
    version.size=sizeof(version);
    if(rtlGetVersion) {
        long status=rtlGetVersion(&version);
        text("OS");field("RtlGetVersionStatus",(DWORD)status);field("Major",version.major);
        field("Minor",version.minor);field("Build",version.build);field("Platform",version.platform);text("\r\n");
    } else text("OS RtlGetVersion=UNAVAILABLE\r\n");
    length=GetModuleFileNameW(0,path,sizeof(path)/sizeof(path[0]));
    if(!length || length>=32768) fail("exe_path",GetLastError(),3);
    for(i=0;i<length;++i) if(path[i]=='\\' || path[i]=='/') directoryEnd=i+1;
    if(directoryEnd+sizeof(ownFixture)/sizeof(ownFixture[0])>32768) fail("fixture_path",0,3);
    for(i=0;i<sizeof(ownFixture)/sizeof(ownFixture[0]);++i) path[directoryEnd+i]=ownFixture[i];
    file=CreateFileW(path,GENERIC_READ,1,0,3,0x80,0);
    if(file==INVALID_HANDLE) fail("open_fixture_readonly",GetLastError(),4);
    diskSize=GetFileSize(file,&sizeHigh);
    if(sizeHigh || diskSize<512 || diskSize>0x100000) fail("fixture_file_size",GetLastError(),4);
    if(!ReadFile(file,headers,sizeof(headers),&count,0) || count<512) fail("fixture_headers",GetLastError(),5);
    if(u16(0)!=0x5a4d) fail("fixture_MZ",0,5);
    pe=u32(0x3c);
    if(pe>sizeof(headers)-256 || u32(pe)!=0x4550 || u16(pe+4)!=0x14c) fail("fixture_PE32",0,5);
    optional=pe+24;
    if(u16(optional)!=0x10b) fail("fixture_magic",0,5);
    entryRva=u32(optional+16);tlsRva=u32(optional+96+9*8);
    if(entryRva || tlsRva) fail("fixture_must_be_inert",0,5);
    imageSize=u32(optional+56);imports=u32(optional+96+8);
    if(imageSize>0x100000 || imageSize<4096 || !imports || imports>imageSize-20)
        fail("fixture_image_bounds",0,5);
    sections=u16(pe+6);sectionTable=optional+u16(pe+20);
    if(!sections || sections>16 || sectionTable>sizeof(headers)-sections*40)
        fail("fixture_sections",0,5);
    mapping=CreateFileMappingW(file,0,SEC_IMAGE|2,0,0,0);
    if(!mapping) fail("CreateFileMapping_SEC_IMAGE",GetLastError(),6);
    controlView=MapViewOfFile(mapping,1,0,0,0);
    if(!controlView) fail("MapView_unloaded",GetLastError(),7);
    image=(BYTE *)controlView;
    at=imports;
    if(!ascii_equal(image,*(DWORD *)(image+at+12),imageSize,"user32.dll"))
        fail("fixture_import_module",0,5);
    ilt=*(DWORD *)(image+at);iat=*(DWORD *)(image+at+16);
    if(!ilt || ilt>imageSize-8 || !iat || iat>imageSize-8 ||
       *(DWORD *)(image+ilt+4) || *(DWORD *)(image+iat+4))
        fail("fixture_single_import",0,5);
    at=*(DWORD *)(image+ilt);
    if(at>imageSize-3 || !ascii_equal(image,at+2,imageSize,"MessageBoxW"))
        fail("fixture_import_symbol",0,5);
    for(i=0;i<sections;++i) {
        DWORD section=sectionTable+40*i,rva=u32(section+12),size=u32(section+8);
        if(rva<=iat && iat-rva<size) {
            sectionFlags=u32(section+36);
            if(!ascii_equal(headers,section,sizeof(headers),".xsv4"))
                fail("fixture_IAT_section_name",0,5);
        }
    }
    if(sectionFlags!=0xc0000040 || system.pageSize!=4096) fail("fixture_IAT_flags",sectionFlags,5);
    rawBefore=*(volatile DWORD *)(image+iat);
    text("FIXTURE");field("IatRva",iat);field("Characteristics",sectionFlags);
    field("FileSize",diskSize);field("EntryPoint",entryRva);field("TLS",tlsRva);
    text(" Import=USER32.MessageBoxW\r\n");
    mappedBefore=query("before_load","unloaded",image+iat);
    loaded=LoadLibraryW(path); /* Own fixture has neither DllMain nor TLS. */
    if(!loaded) fail("LoadLibrary_own_fixture",GetLastError(),8);
    expectedValue=(DWORD)GetProcAddress(GetModuleHandleW(user32Name),"MessageBoxW");
    if(!expectedValue) fail("GetProcAddress_MessageBoxW",GetLastError(),9);
    loadedValue=*(volatile DWORD *)((BYTE *)loaded+iat);
    loadedInfo=query("after_load","loaded",(BYTE *)loaded+iat);
    mappedAfter=query("after_load","unloaded",image+iat);
    rawAfter=*(volatile DWORD *)(image+iat);
    text("IMPORT");field("Expected",expectedValue);field("LoadedIat",loadedValue);
    field("UnloadedBefore",rawBefore);field("UnloadedAfter",rawAfter);
    text(" resolution=");text(loadedValue==expectedValue ? "PASS" : "FAIL");
    text(" isolation=");text(rawBefore==rawAfter ? "PASS" : "FAIL");text("\r\n");
    if(loadedValue!=expectedValue || rawBefore!=rawAfter) fail("IAT_resolution_or_isolation",0,10);
    if(mappedBefore.State!=MEM_COMMIT || mappedAfter.State!=MEM_COMMIT || loadedInfo.State!=MEM_COMMIT ||
       mappedBefore.Type!=SEC_IMAGE || mappedAfter.Type!=SEC_IMAGE || loadedInfo.Type!=SEC_IMAGE ||
       loadedInfo.AllocationBase!=(DWORD)loaded || mappedBefore.AllocationBase!=(DWORD)controlView ||
       mappedAfter.AllocationBase!=(DWORD)controlView)
        fail("mapping_identity",0,11);
    text("OBSERVATION");field("UnloadedProtect",mappedBefore.Protect);field("LoadedIatProtect",loadedInfo.Protect);
    text(" ImportResolved=YES OwnEntryPointCalled=NO ManualStores=0\r\n");
    if(!FreeLibrary(loaded)) fail("FreeLibrary_own_fixture",GetLastError(),12);
    text("COMPLETE probe_exit=0x00000000\r\n");
    clean();ExitProcess(0);
}
