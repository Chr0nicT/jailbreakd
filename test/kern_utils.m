#import <Foundation/Foundation.h>
#include <sched.h>
#include <sys/stat.h>
#include "kern_utils.h"
#include "kexecute.h"
#include "kmem.h"
#include "offsetof.h"
#include "osobject.h"
#include "sandbox.h"
#include "vnode_utils.h"
#include "offsets.h"
#include "OffsetHolder.h"
#include <spawn.h>
#include "cs_blob.h"

#define DEBUGLOG(bool, msg, args...) do { \
fprintf(stderr, msg, ##args); \
} while(0)

mach_port_t tfp0;
uint64_t kernel_base;
uint64_t kernel_slide;

uint64_t kernprocaddr;
uint64_t offset_zonemap;

uint64_t offset_add_ret_gadget;
uint64_t offset_osboolean_true;
uint64_t offset_osboolean_false;
uint64_t offset_osunserializexml;
uint64_t offset_smalloc;
uint64_t offset_kernel_task;
uint64_t offset_paciza_pointer__l2tp_domain_module_start;
uint64_t offset_paciza_pointer__l2tp_domain_module_stop;
uint64_t offset_l2tp_domain_inited;
uint64_t offset_sysctl__net_ppp_l2tp;
uint64_t offset_sysctl_unregister_oid;
uint64_t offset_proc_rele;
uint64_t offset_mov_x0_x4__br_x5;
uint64_t offset_mov_x9_x0__br_x1;
uint64_t offset_mov_x10_x3__br_x6;
uint64_t offset_kernel_forge_pacia_gadget;
uint64_t offset_kernel_forge_pacda_gadget;
uint64_t offset_IOUserClient__vtable;
uint64_t offset_IORegistryEntry__getRegistryEntryID;

uint64_t offset_vfs_context_current;
uint64_t offset_vnode_lookup;
uint64_t offset_vnode_put;

// Please call `proc_release` after you are finished with your proc!
uint64_t proc_find(int pd) {
    uint64_t proc = kernprocaddr;
    
    while (proc) {
        uint32_t found_pid = rk32(proc + offsetof_p_pid);
        
        if (found_pid == pd) {
            return proc;
        }
        
        proc = rk64(proc + 0x8);
    }
    
    return 0;
}

uint64_t our_task_addr() {
    uint64_t proc = rk64(kernprocaddr + 0x8);
    
    while (proc) {
        uint32_t proc_pid = rk32(proc + offsetof_p_pid);
        
        if (proc_pid == getpid()) {
            break;
        }
        
        proc = rk64(proc + 0x8);
    }
    
    if (proc == 0) {
        DEBUGLOG(false, "failed to find our_task_addr!");
        exit(EXIT_FAILURE);
    }

    return rk64(proc + offsetof_task);
}

uint64_t find_port(mach_port_name_t port) {
    uint64_t task_addr = our_task_addr();
  
    uint64_t itk_space = rk64(task_addr + offsetof_itk_space);
  
    uint64_t is_table = rk64(itk_space + offsetof_ipc_space_is_table);
  
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
  
    return rk64(is_table + (port_index * sizeof_ipc_entry_t));
}

void unsandbox(int pid) {
    uint64_t proc = proc_find(pid);
    uint64_t ucred = rk64(proc + off_p_ucred);
    uint64_t cr_label = rk64(ucred + off_ucred_cr_label);
    wk64(cr_label + off_sandbox_slot, 0);
    DEBUGLOG(false, "UNSANDBOX RETURNED: 0 (SUCCESS)");
}


/*
void fixupsetuid(int pid) {
    uint64_t proc = proc_find(pid);
    uint64_t ucred = rk64(proc + off_p_ucred);
    wk32(proc + off_p_gid, 0);
    wk32(proc + off_p_rgid, 0);
    wk32(ucred + off_ucred_cr_rgid, 0);
    wk32(ucred + off_ucred_cr_svgid, 0);
    wk32(proc + off_p_uid, 0);
    wk32(proc + off_p_ruid, 0);
    wk32(ucred + off_ucred_cr_uid, 0);
    wk32(ucred + off_ucred_cr_ruid, 0);
    wk32(ucred + off_ucred_cr_svuid, 0);
    DEBUGLOG(false, "SET UID AND GID TO 0");
}
 */
void fixupsetuid(int pid)
{
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));
    
    int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if (ret < 0) {
        DEBUGLOG(false, "Unable to get path for PID %d", pid);
        return;
    }
    
    struct stat file_st;
    if (lstat(pathbuf, &file_st) == -1) {
        DEBUGLOG(false, "Unable to get stat for file %s", pathbuf);
        return;
    }
    
    if (!(file_st.st_mode & S_ISUID) && !(file_st.st_mode & S_ISGID)) {
        DEBUGLOG(false, "File is not setuid or setgid: %s", pathbuf);
        return;
    }
    
    uint64_t proc = proc_find(pid);
    if (proc == 0) {
        DEBUGLOG(false, "Unable to find proc for pid %d", pid);
        return;
    }
    
    DEBUGLOG(false, "Found proc %llx for pid %d", proc, pid);
    
    uid_t fileUid = file_st.st_uid;
    gid_t fileGid = file_st.st_gid;
    
    DEBUGLOG(false, "Applying UID %d to process %d", fileUid, pid);
    uint64_t ucred = rk64(proc + offsetof_p_ucred);
    
    if (file_st.st_mode & S_ISUID) {
        wk32(proc + offsetof_p_svuid, fileUid);
        wk32(ucred + offsetof_ucred_cr_svuid, fileUid);
        wk32(ucred + offsetof_ucred_cr_uid, fileUid);
    }
    
    if (file_st.st_mode & S_ISGID) {
        wk32(proc + offsetof_p_svgid, fileGid);
        wk32(ucred + offsetof_ucred_cr_svgid, fileGid);
        wk32(ucred + offsetof_ucred_cr_groups, fileGid);
    }
}

void set_csflags(uint64_t proc) {
    
    uint32_t csflags = rk32(proc + offsetof_p_csflags);
    uint32_t new_csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    
    if (csflags != new_csflags)
    {
        wk32(proc + offsetof_p_csflags, new_csflags);
    }
    
}

void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    uint64_t task = rk64(proc + offsetof_task);
    uint32_t t_flags = rk32(task + offsetof_t_flags);
    t_flags |= TF_PLATFORM;
    wk32(task+offsetof_t_flags, t_flags);
    
}

void set_csblob(uint64_t proc) {
    uint64_t textvp = rk64(proc + offsetof_p_textvp); // vnode of executable
    if (textvp == 0) return;
    
    uint16_t vnode_type = rk16(textvp + offsetof_v_type);
    if (vnode_type != 1) return; // 1 = VREG
    
    uint64_t ubcinfo = rk64(textvp + offsetof_v_ubcinfo);

    // Loop through all csblob entries (linked list) and update
    // all (they must match by design)
    uint64_t csblob = rk64(ubcinfo + offsetof_ubcinfo_csblobs);
    while (csblob != 0) {
        wk32(csblob + offsetof_csb_platform_binary, 1);
        
        csblob = rk64(csblob);
    }
}

const char* abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/private/var/mnt",
    "/System/Library/Caches",
    NULL
};

uint64_t exception_osarray_cache = 0;
uint64_t get_exception_osarray(void) {
    if (exception_osarray_cache == 0) {
        exception_osarray_cache = OSUnserializeXML(
            "<array>"
            "<string>/Library/</string>"
            "<string>/private/var/mobile/Library/</string>"
            "<string>/private/var/mnt/</string>"
            "<string>/System/Library/Caches/</string>"
            "</array>"
        );
    }

    return exception_osarray_cache;
}

static const char *exc_key = "com.apple.security.exception.files.absolute-path.read-only";

void set_sandbox_extensions(uint64_t proc) {
    uint64_t proc_ucred = rk64(proc + offsetof_p_ucred);
    uint64_t sandbox = rk64(rk64(proc_ucred + 0x78) + 0x10);
    
    
    if (sandbox == 0) {
        return;
    }
    
    if (has_file_extension(sandbox, abs_path_exceptions[0])) {
        return;
    }
    
    uint64_t ext = 0;
    const char** path = abs_path_exceptions;
    while (*path != NULL) {
        ext = extension_create_file(*path, ext);
        if (ext == 0) {
        }
        ++path;
    }
    
    
    if (ext != 0) {
        extension_add(ext, sandbox, exc_key);
    }
}


void set_amfi_entitlements(uint64_t proc) {
    uint64_t proc_ucred = rk64(proc + offsetof_p_ucred);
    uint64_t amfi_entitlements = rk64(rk64(proc_ucred + 0x78) + 0x8);

    int rv = 0;

    if (OSDictionary_GetItem(amfi_entitlements, "get-task-allow") != offset_osboolean_true)
    {
        OSDictionary_SetItem(amfi_entitlements, "get-task-allow", offset_osboolean_true);
    }
    
    if (OSDictionary_GetItem(amfi_entitlements, "com.apple.private.skip-library-validation") != offset_osboolean_true)
    {
        OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", offset_osboolean_true);
    }
    
    uint64_t present = OSDictionary_GetItem(amfi_entitlements, exc_key);

    if (present == 0) {
        rv = OSDictionary_SetItem(amfi_entitlements, exc_key, get_exception_osarray());
        DEBUGLOG(false, "PRESENT ERROR");
    } else if (present != get_exception_osarray()) {
        unsigned int itemCount = OSArray_ItemCount(present);
        DEBUGLOG(false, "got item count: %d", itemCount);

        BOOL foundEntitlements = NO;

        uint64_t itemBuffer = OSArray_ItemBuffer(present);

        for (int i = 0; i < itemCount; i++) {
            uint64_t item = rk64(itemBuffer + (i * sizeof(void *)));
            char *entitlementString = OSString_CopyString(item);
            DEBUGLOG(false, "found ent string: %s", entitlementString);
            if (strcmp(entitlementString, "/Library/") == 0) {
                foundEntitlements = YES;
                free(entitlementString);
                break;
            }
            free(entitlementString);
        }

        if (!foundEntitlements){
            rv = OSArray_Merge(present, get_exception_osarray());
        } else {
            rv = 1;
        }
    } else {
        rv = 1;
    }

    if (rv != 1) {
        DEBUGLOG(false, "Setting exc FAILED! amfi_entitlements: 0x%llx present: 0x%llx", amfi_entitlements, present);
    }
}


void platformize(int pd) {
    
    //fixDylib("/usr/lib/libsubstitute.dylib");
    
    uint64_t proc = proc_find(pd);    
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));
    proc_pidpath(pd, pathbuf, sizeof(pathbuf));
    
    DEBUGLOG(true, "CALLED ON FILE: %s", pathbuf);
    
    
    if (proc == 0) {
        DEBUGLOG(true, "failed to find proc for pid %d!", pd);
        return;
    }
    
    DEBUGLOG(true, "platformize called for %d (proc: %llx)", pd, proc);
    DEBUGLOG(true, "CSFlags");
    set_csflags(proc);
    DEBUGLOG(true, "TFPlatform");
    set_tfplatform(proc);
    DEBUGLOG(true, "AMFI Ents");
    set_amfi_entitlements(proc);
    DEBUGLOG(true, "Sandbox Extensions");
    set_sandbox_extensions(proc);
    DEBUGLOG(true, "Finished!");
}
