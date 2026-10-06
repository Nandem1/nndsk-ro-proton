// SPDX-License-Identifier: LGPL-2.1-or-later
/* PE64 derivative of the preserved own PE32 fixture probe, no CRT. Measure SEC_IMAGE COW; never VirtualProtect or load a DLL.
 * The only memory store to the mapped image is one volatile DWORD write.
 * CREATE_NEW evidence file; all inputs are own fixture + current process.
 */
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef void *HANDLE;
typedef __UINTPTR_TYPE__ SIZE_T;
#define API __declspec(dllimport) __stdcall
#define INVALID_HANDLE ((HANDLE)-1)
#define GENERIC_READ 0x80000000
#define SEC_IMAGE 0x01000000
#define MEM_COMMIT 0x1000
#define PAGE_READWRITE 4
#define PAGE_WRITECOPY 8
typedef struct { void *BaseAddress, *AllocationBase; DWORD AllocationProtect;
    WORD PartitionId; SIZE_T RegionSize; DWORD State, Protect, Type; } MBI64;
typedef struct { WORD architecture,reserved; DWORD pageSize;
    void *minimum,*maximum; SIZE_T processorMask; DWORD processors, processorType,
    allocationGranularity; WORD processorLevel,processorRevision; } SYSTEM_INFO64;
typedef struct { DWORD size,major,minor,build,platform; WORD servicePack[128]; } VERSION32;
typedef char assert_pointer64[sizeof(void *) == 8 ? 1 : -1];
typedef char assert_dword32[sizeof(DWORD) == 4 ? 1 : -1];
typedef char assert_mbi48[sizeof(MBI64) == 48 ? 1 : -1];
typedef char assert_system48[sizeof(SYSTEM_INFO64) == 48 ? 1 : -1];
typedef char assert_version276[sizeof(VERSION32) == 276 ? 1 : -1];
API HANDLE CreateFileW(const WORD *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
API HANDLE CreateFileMappingW(HANDLE,void *,DWORD,DWORD,DWORD,const WORD *);
API void *MapViewOfFile(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
API BOOL UnmapViewOfFile(const void *);
API BOOL CloseHandle(HANDLE);
API BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
API DWORD SetFilePointer(HANDLE,long,long *,DWORD);
API DWORD GetFileSize(HANDLE,DWORD *);
API DWORD GetModuleFileNameW(HANDLE,WORD *,DWORD);
API HANDLE GetModuleHandleW(const WORD *);
API void *GetProcAddress(HANDLE,const char *);
API SIZE_T VirtualQuery(const void *,MBI64 *,SIZE_T);
API void GetNativeSystemInfo(SYSTEM_INFO64 *);
API DWORD GetCurrentProcessId(void);
API HANDLE GetStdHandle(DWORD);
API BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
API BOOL FlushFileBuffers(HANDLE);
API DWORD GetLastError(void);
API void SetLastError(DWORD);
API void ExitProcess(DWORD);
static HANDLE output=INVALID_HANDLE, file=INVALID_HANDLE, mapping;
static void *targetView,*controlView;
static BYTE headers[4096];
static WORD path[32768];
static const WORD fixtureName[]={'c','o','w','-','f','i','x','t','u','r','e','.','d','l','l',0};
static const WORD ntdllName[]={'n','t','d','l','l','.','d','l','l',0};

/* Compiler-generated aggregate moves/initialization, no CRT dependency. */
void *memset(void *destination,int value,SIZE_T size) {
    volatile BYTE *p=(volatile BYTE *)destination;
    while(size--) *p++=(BYTE)value;
    return destination;
}
void *memcpy(void *destination,const void *source,SIZE_T size) {
    volatile BYTE *d=(volatile BYTE *)destination;
    const volatile BYTE *s=(const volatile BYTE *)source;
    while(size--) *d++=*s++;
    return destination;
}

static void raw(HANDLE h,const char *s,DWORD length) {
    DWORD count;
    while (length) {
        if (!WriteFile(h,s,length,&count,0) || !count) ExitProcess(90);
        s+=count; length-=count;
    }
}
static void text(const char *s) {
    DWORD length=0;
    while(s[length]) ++length;
    raw(output,s,length);
}
static void hex(SIZE_T value) {
    const char digits[]="0123456789abcdef";
    char result[]="0x0000000000000000";
    DWORD i;
    for(i=0;i<16;++i) result[17-i]=digits[(value>>(4*i))&15];
    text(result);
}
static void field(const char *name,SIZE_T value) { text(" ");text(name);text("=");hex(value); }
static void clean(void) {
    if(controlView) { UnmapViewOfFile(controlView);controlView=0; }
    if(targetView) { UnmapViewOfFile(targetView);targetView=0; }
    if(mapping) { CloseHandle(mapping);mapping=0; }
    if(file!=INVALID_HANDLE) { CloseHandle(file);file=INVALID_HANDLE; }
    if(output!=INVALID_HANDLE) { FlushFileBuffers(output);CloseHandle(output);output=INVALID_HANDLE; }
}
static void fail(const char *stage,DWORD error,DWORD status) {
    text("FAIL stage=");text(stage);field("error",error);field("probe_exit",status);text("\r\n");
    clean();ExitProcess(status);
}
static DWORD u32(DWORD offset) {
    if(offset>sizeof(headers)-4) fail("header_bounds",0,10);
    return (DWORD)headers[offset]|((DWORD)headers[offset+1]<<8)|
        ((DWORD)headers[offset+2]<<16)|((DWORD)headers[offset+3]<<24);
}
static DWORD u16(DWORD offset) {
    if(offset>sizeof(headers)-2) fail("header_bounds",0,10);
    return (DWORD)headers[offset]|((DWORD)headers[offset+1]<<8);
}
static DWORD disk_word(DWORD offset) {
    DWORD result=0,count=0;
    SetLastError(0);
    if(SetFilePointer(file,(long)offset,0,0)==0xffffffff && GetLastError())
        fail("seek_fixture",GetLastError(),11);
    if(!ReadFile(file,&result,4,&count,0) || count!=4)
        fail("read_fixture_word",GetLastError(),11);
    return result;
}
static MBI64 query(const char *phase,const char *view,const void *address) {
    MBI64 m={0};
    DWORD bytes,error;
    SetLastError(0);
    bytes=VirtualQuery(address,&m,sizeof(m));error=GetLastError();
    text("QUERY phase=");text(phase);text(" view=");text(view);
    field("Address",(SIZE_T)address);field("ReturnBytes",bytes);field("LastError",error);
    field("AllocationProtect",m.AllocationProtect);field("Protect",m.Protect);
    field("State",m.State);field("Type",m.Type);field("RegionSize",m.RegionSize);
    field("BaseAddress",(SIZE_T)m.BaseAddress);field("AllocationBase",(SIZE_T)m.AllocationBase);text("\r\n");
    if(bytes!=sizeof(m)) fail("VirtualQuery_size",error,12);
    if(!FlushFileBuffers(output)) fail("flush_evidence",GetLastError(),13);
    return m;
}
void entry(void) {
    DWORD length,i,directoryEnd=0,pe,optional,sectionTable,sections,rva=0,rawOffset=0;
    DWORD count,characteristics=0,original,changed,after,control,disk,sizeHigh=0;
    volatile DWORD *slot,*controlSlot;
    MBI64 before,afterInfo;
    SYSTEM_INFO64 system={0};
    VERSION32 version={0};
    long (__stdcall *rtlGetVersion)(VERSION32 *);
    output=CreateFileA("cow-probe-result.txt",0x40000000,1,0,1,0x80,0);
    if(output==INVALID_HANDLE) {
        const char msg[]="Refusing to overwrite cow-probe-result.txt (or output unavailable).\r\n";
        HANDLE standard=GetStdHandle((DWORD)-11);
        if(standard && standard!=INVALID_HANDLE) raw(standard,msg,sizeof(msg)-1);
        ExitProcess(2);
    }
    text("COW_PROBE protocol=2 arch=PE64 fixture=cow-fixture.dll mapping=SEC_IMAGE writes=1 no_VirtualProtect=1 no_LoadLibrary=1\r\n");
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
    if(directoryEnd+sizeof(fixtureName)/sizeof(fixtureName[0])>32768) fail("fixture_path",0,3);
    for(i=0;i<sizeof(fixtureName)/sizeof(fixtureName[0]);++i) path[directoryEnd+i]=fixtureName[i];
    file=CreateFileW(path,GENERIC_READ,1,0,3,0x80,0);
    if(file==INVALID_HANDLE) fail("open_fixture_readonly",GetLastError(),4);
    length=GetFileSize(file,&sizeHigh);
    if(sizeHigh || length<512 || length>0x100000) fail("fixture_file_size",GetLastError(),4);
    if(!ReadFile(file,headers,sizeof(headers),&count,0) || count<512) fail("fixture_headers",GetLastError(),5);
    if(u16(0)!=0x5a4d) fail("fixture_MZ",0,5);
    pe=u32(0x3c);
    if(pe>sizeof(headers)-256 || u32(pe)!=0x4550 || u16(pe+4)!=0x8664) fail("fixture_PE64",0,5);
    optional=pe+24;
    if(u16(optional)!=0x20b) fail("fixture_magic",0,5);
    sections=u16(pe+6);sectionTable=optional+u16(pe+20);
    if(!sections || sections>16 || sectionTable>sizeof(headers)-sections*40) fail("fixture_sections",0,5);
    for(i=0;i<sections;++i) {
        DWORD at=sectionTable+40*i;
        if(headers[at]=='.' && headers[at+1]=='c' && headers[at+2]=='o' && headers[at+3]=='w' &&
            headers[at+4]=='p' && headers[at+5]=='g' && headers[at+6]==0) {
            rva=u32(at+12);rawOffset=u32(at+20);characteristics=u32(at+36);
            if(u32(at+8)!=4096 || u32(at+16)!=4096) fail("fixture_page_size",0,5);
        }
    }
    if(!rva || system.pageSize!=4096 || rva%4096 ||
       (characteristics&0xe0000000)!=0xc0000000 || rawOffset>length-4)
        fail("fixture_RW_nonexec_page",0,5);
    original=disk_word(rawOffset);
    if(original!=0xdf9b5731) fail("fixture_initial_word",original,5);
    text("FIXTURE");field("Rva",rva);field("RawOffset",rawOffset);field("Characteristics",characteristics);
    field("FileSize",length);field("Original",original);text("\r\n");
    mapping=CreateFileMappingW(file,0,SEC_IMAGE|2,0,0,0);
    if(!mapping) fail("CreateFileMapping_SEC_IMAGE",GetLastError(),6);
    targetView=MapViewOfFile(mapping,1,0,0,0);
    if(!targetView) fail("MapView_target",GetLastError(),7);
    controlView=MapViewOfFile(mapping,1,0,0,0);
    if(!controlView) fail("MapView_control",GetLastError(),8);
    slot=(volatile DWORD *)((BYTE *)targetView+rva);
    controlSlot=(volatile DWORD *)((BYTE *)controlView+rva);
    before=query("before","target",(const void *)slot);
    query("before","control",(const void *)controlSlot);
    if(before.State!=MEM_COMMIT || before.Type!=SEC_IMAGE || before.AllocationBase!=targetView ||
       (before.Protect!=PAGE_WRITECOPY && before.Protect!=PAGE_READWRITE))
        fail("unsafe_before_write",before.Protect,14);
    if(*slot!=original || *controlSlot!=original) fail("initial_views",0,15);
    changed=original^0x01020304;
    *slot=changed; /* Exactly one store to the own image, no protection change. */
    after=*slot;control=*controlSlot;
    afterInfo=query("after","target",(const void *)slot);
    query("after","control",(const void *)controlSlot);
    disk=disk_word(rawOffset);
    text("WRITE");field("Before",original);field("Intended",changed);field("After",after);
    field("ControlAfter",control);field("DiskAfter",disk);text("\r\n");
    if(after!=changed || control!=original || disk!=original) fail("COW_isolation",0,16);
    if(afterInfo.State!=MEM_COMMIT || afterInfo.Type!=SEC_IMAGE || afterInfo.AllocationBase!=targetView)
        fail("after_image_identity",0,17);
    text("OBSERVATION");field("ProtectBefore",before.Protect);field("ProtectAfter",afterInfo.Protect);
    text(" isolation=PASS");
    if(before.Protect!=PAGE_WRITECOPY) text(" pending_COW_before=NO");
    else text(" pending_COW_before=YES");
    text("\r\nCOMPLETE probe_exit=0x00000000\r\n");
    clean();ExitProcess(0);
}
