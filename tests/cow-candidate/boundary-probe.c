/* Own PE32 fixtures only. Observe CPU, IO, wineserver and protection lifecycle. */
#define entry original_probe_not_executed
#include "../cow-probe/probe.c"
#undef entry

API BOOL VirtualProtect(void *, SIZE_T, DWORD, DWORD *);
API void *VirtualAlloc(void *, SIZE_T, DWORD, DWORD);
API BOOL VirtualFree(void *, SIZE_T, DWORD);
API DWORD GetWriteWatch(DWORD, void *, SIZE_T, void **, SIZE_T *, DWORD *);
API DWORD ResetWriteWatch(void *, SIZE_T);
typedef struct { DWORD code,flags; void *nested,*address; DWORD count,info[15]; } ER32;
typedef struct { ER32 *record; void *context; } EP32;
API void *AddVectoredExceptionHandler(DWORD, long (__stdcall *)(EP32 *));
API DWORD RemoveVectoredExceptionHandler(void *);
static DWORD initialPages[4096], guardCount, guardProtect;
static void *guardPage;
static long (__stdcall *ntWrite)(HANDLE,void *,const void *,SIZE_T,SIZE_T *);
static long (__stdcall *ntRead)(HANDLE,const void *,void *,SIZE_T,SIZE_T *);

static void views(void) {
    if(targetView) UnmapViewOfFile(targetView);
    if(controlView) UnmapViewOfFile(controlView);
    targetView=MapViewOfFile(mapping,1,0,0,0);
    controlView=MapViewOfFile(mapping,1,0,0,0);
    if(!targetView || !controlView) fail("own_copy_views",GetLastError(),30);
}
static void check(const char *name,DWORD expectedMask,DWORD dataMask) {
    DWORD i,observed=0;
    for(i=0;i<4;i++) {
        const volatile DWORD *t=(const volatile DWORD *)((const BYTE *)targetView+4096*i);
        const volatile DWORD *c=(const volatile DWORD *)((const BYTE *)controlView+4096*i);
        MBI32 m=query(name,"target",(const void *)t);
        MBI32 cm=query(name,"control",(const void *)c);
        if(m.Protect==4) observed|=1<<i;
        /* VirtualQuery starts its forward region at the queried page. */
        if((m.Protect!=4 && m.Protect!=8) || cm.Protect!=8 || cm.RegionSize!=16384-4096*i ||
           m.Type!=0x40000 || cm.Type!=0x40000 || m.State!=0x1000 ||
           m.AllocationBase!=(DWORD)targetView || cm.AllocationBase!=(DWORD)controlView)
            fail("own_mapping_identity",m.Protect,31);
        if(*t!=((dataMask&(1<<i))?0xde995435:0xdf9b5731) || *c!=0xdf9b5731 ||
           disk_word(4096*i)!=0xdf9b5731) fail("own_fixture_isolation",i,32);
    }
    text("CASE name=");text(name);field("ExpectedCopiedMask",expectedMask);
    field("ObservedCopiedMask",observed);text(" isolation=PASS\r\n");
}
static long __stdcall guard_handler(EP32 *p) {
    MBI32 info;
    if(p->record->code!=0x80000001) return 0;
    ++guardCount;
    if(VirtualQuery(guardPage,&info,28)==28) guardProtect=info.Protect;
    return -1;
}
void entry(void) {
    HANDLE fixture,input;
    DWORD i,count,old,changed=0xde995435,granularity,status;
    SIZE_T written,watchedCount;
    void *handler,*watched,*addresses[4];
    MBI32 info;
    long ntStatus;
    output=CreateFileA("boundary-probe-result.txt",0x40000000,1,0,1,0x80,0);
    if(output==INVALID_HANDLE) ExitProcess(2);
    text("BOUNDARY_PROBE protocol=1 arch=PE32 own_fixtures_only=1\r\n");
    for(i=0;i<4096;i++) initialPages[i]=0xdf9b5731;
    fixture=CreateFileA("own-cow-pages.bin",0x40000000,1,0,1,0x80,0);
    if(fixture==INVALID_HANDLE || !WriteFile(fixture,initialPages,sizeof(initialPages),&count,0) ||
       count!=sizeof(initialPages)) fail("create_own_fixture",GetLastError(),33);
    CloseHandle(fixture);
    file=CreateFileA("own-cow-pages.bin",0x80000000,1,0,3,0x80,0);
    if(file==INVALID_HANDLE) fail("open_own_fixture_readonly",GetLastError(),33);
    mapping=CreateFileMappingW(file,0,8,0,0,0);
    if(!mapping) fail("create_own_copy_mapping",GetLastError(),34);

    views(); check("virgin",0,0);
    *(volatile DWORD *)targetView=changed;
    check("cpu",1,1);

    input=CreateFileA("own-io-input.bin",0xc0000000,1,0,1,0x80,0);
    if(input==INVALID_HANDLE || !WriteFile(input,&changed,4,&count,0) || count!=4 ||
       SetFilePointer(input,0,0,0)!=0) fail("create_own_io_input",GetLastError(),35);
    views();
    if(!ReadFile(input,(BYTE *)targetView+4096,4,&count,0) || count!=4)
        fail("ReadFile_to_copy",GetLastError(),35);
    CloseHandle(input);
    text("API name=ReadFile");field("Return",1);field("Bytes",count);text("\r\n");
    check("file_io",2,2);

    ntWrite=(long (__stdcall *)(HANDLE,void *,const void *,SIZE_T,SIZE_T *))
        GetProcAddress(GetModuleHandleW(ntdllName),"NtWriteVirtualMemory");
    ntRead=(long (__stdcall *)(HANDLE,const void *,void *,SIZE_T,SIZE_T *))
        GetProcAddress(GetModuleHandleW(ntdllName),"NtReadVirtualMemory");
    if(!ntWrite || !ntRead) fail("resolve_memory_apis",GetLastError(),36);
    views(); written=0;
    ntStatus=ntWrite((HANDLE)-1,(BYTE *)targetView+8192,&changed,4,&written);
    text("API name=NtWriteVirtualMemory_self");field("Status",(DWORD)ntStatus);
    field("Bytes",written);text("\r\n");
    if(ntStatus || written!=4) fail("NtWriteVirtualMemory_to_copy",(DWORD)ntStatus,36);
    check("wineserver_write",4,4);

    views(); written=0;
    ntStatus=ntRead((HANDLE)-1,&changed,(BYTE *)targetView+4096,4,&written);
    text("API name=NtReadVirtualMemory_self");field("Status",(DWORD)ntStatus);
    field("Bytes",written);text("\r\n");
    if(ntStatus || written!=4) fail("NtReadVirtualMemory_to_copy",(DWORD)ntStatus,36);
    check("memory_read_output",2,2);

    views();
    if(!VirtualProtect(targetView,4096,2,&old)) fail("virgin_readonly",GetLastError(),37);
    if(!VirtualProtect(targetView,4096,8,&old)) fail("virgin_restore",GetLastError(),37);
    check("unwritten_restore",0,0);
    *(volatile DWORD *)targetView=changed;
    if(!VirtualProtect(targetView,4096,2,&old)) fail("copied_readonly",GetLastError(),37);
    info=query("copied_readonly","target",targetView);
    if(info.Protect!=2) fail("readonly_contract",info.Protect,37);
    text("PROTECT phase=after_store_readonly");field("OldProtection",old);text("\r\n");
    if(!VirtualProtect(targetView,4096,8,&old)) fail("copied_restore",GetLastError(),37);
    check("written_restore",1,1);

    views(); guardPage=targetView; guardCount=0; guardProtect=0;
    handler=AddVectoredExceptionHandler(1,guard_handler);
    if(!handler || !VirtualProtect(targetView,4096,8|0x100,&old))
        fail("own_guard_setup",GetLastError(),38);
    *(volatile DWORD *)targetView=changed;
    RemoveVectoredExceptionHandler(handler);
    text("GUARD");field("Exceptions",guardCount);field("ProtectAtHandler",guardProtect);text("\r\n");
    if(guardCount!=1 || guardProtect!=8) fail("guard_order",guardProtect,38);
    check("guard_then_store",1,1);

    views(); check("remap",0,0);
    watched=VirtualAlloc(0,4*4096,0x2000|0x1000|0x200000,4);
    if(!watched) fail("own_writewatch_alloc",GetLastError(),39);
    *(volatile DWORD *)watched=1;
    *(volatile DWORD *)((BYTE *)watched+8192)=2;
    watchedCount=4;
    status=GetWriteWatch(0,watched,16384,addresses,&watchedCount,&granularity);
    text("WRITEWATCH phase=written");field("Status",status);field("Count",watchedCount);
    field("Granularity",granularity);text("\r\n");
    if(status || watchedCount!=2 || granularity!=4096) fail("writewatch_written",status,39);
    if(ResetWriteWatch(watched,16384)) fail("writewatch_reset",GetLastError(),39);
    watchedCount=4;
    status=GetWriteWatch(0,watched,16384,addresses,&watchedCount,&granularity);
    text("WRITEWATCH phase=reset");field("Status",status);field("Count",watchedCount);text("\r\n");
    if(status || watchedCount) fail("writewatch_after_reset",status,39);
    VirtualFree(watched,0,0x8000);
    text("COMPLETE probe_exit=0x00000000\r\n");
    clean(); ExitProcess(0);
}
