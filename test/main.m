#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/error.h>
#include "jailbreak_daemonServer.h"
#include "kern_utils.h"
#include "kexecute.h"
#include "kmem.h"

#define DEBUGLOG(bool, msg, args...) do { \
} while(0)

#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define JAILBREAKD_COMMAND_ENTITLE                              1
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT                  2
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY    3
#define JAILBREAKD_COMMAND_FIXUP_SETUID                         4
#define JAILBREAKD_COMMAND_FIXUP_DYLIB                          5

typedef boolean_t (*dispatch_mig_callback_t)(mach_msg_header_t *message, mach_msg_header_t *reply);
mach_msg_return_t dispatch_mig_server(dispatch_source_t ds, size_t maxmsgsz, dispatch_mig_callback_t callback);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service, mach_port_t *server_port);

dispatch_queue_t queue = NULL;

int is_valid_command(uint8_t command) {
    return (command == JAILBREAKD_COMMAND_ENTITLE ||
            command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT ||
            command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY ||
            command == JAILBREAKD_COMMAND_FIXUP_SETUID ||
            command == JAILBREAKD_COMMAND_FIXUP_DYLIB);
}

int handle_command(uint8_t command, uint32_t pid) {
    if (!is_valid_command(command)) {
        DEBUGLOG(true, "Invalid command recieved.");
        return 1;
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE) {
        DEBUGLOG(true, "JAILBREAKD_COMMAND_ENTITLE PID: %d", pid);
        platformize(pid);
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT) {
        DEBUGLOG(true, "JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT PID: %d", pid);
        platformize(pid);
        kill(pid, SIGCONT);
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY) {
        DEBUGLOG(true, "JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY PID: %d", pid);
        
        dispatch_async(queue, ^{
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathbuf, PROC_PIDPATHINFO_MAXSIZE);
            
            int err = 0, tries = 0;
            
            do {
                err = proc_pidpath(pid, pathbuf, PROC_PIDPATHINFO_MAXSIZE);
                if (err <= 0) {
                    DEBUGLOG(true, "failed to get pidpath for %d", pid);
                    kill(pid, SIGCONT); // just in case
                    return;
                }
                
                tries++;
                // gives (1,000 * 1,000 microseconds) 1 seconds of total wait time
                if (tries >= 1000) {
                    DEBUGLOG(true, "failed to get pidpath for %d (%d tries)", pid, tries);
                    kill(pid, SIGCONT); // just in case
                    return;
                }
                
                usleep(1000);
            } while (strcmp(pathbuf, "/usr/libexec/xpcproxy") == 0 || strcmp(pathbuf, "/usr/libexec/xpcproxy.sliced") == 0);
            
            DEBUGLOG(true, "xpcproxy has morphed to: %s", pathbuf);
            platformize(pid);
            kill(pid, SIGCONT);
        });
    }
    
    if (command == JAILBREAKD_COMMAND_FIXUP_SETUID) {
        if (kCFCoreFoundationVersionNumber >= 1443.00) {
            DEBUGLOG(true, "JAILBREAKD_FIXUP_SETUID PID: %d", pid);
            fixupsetuid(pid);
        } else {
            DEBUGLOG(true, "JAILBREAKD_FIXUP_SETUID PID: %d (ignored)", pid);
        }
    }
    
    if (command == JAILBREAKD_COMMAND_FIXUP_DYLIB) {
        //fixDylib("/usr/lib/libsubstitute.dylib");
        DEBUGLOG(true, "DEPRECATED");
    }
    
    return 0;
}

kern_return_t jbd_call(mach_port_t server_port, uint8_t command, uint32_t pid) {
    DEBUGLOG(false, "jbd_call: %x, %x, %d", server_port, command, pid);
    kern_return_t ret = (handle_command(command, pid) == 0) ? KERN_SUCCESS : KERN_FAILURE;
    DEBUGLOG(false, "jbd_call complete: %d", ret);
    return ret;
}

uint64_t getCachedOffset(NSString *off)
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/ziyou/offsets.plist"];
    uint64_t offsetName = (uint64_t)strtoull([offsets[off] UTF8String], NULL, 16);
    
    DEBUGLOG(false, "%s: 0x%016llx", [off UTF8String], offsetName);
    
    return offsetName;
}

int main(int argc, char **argv, char **envp) {
    kern_return_t err;
    
    DEBUGLOG(true, "[JAILBREAKD] INIT!");
    unlink("/var/tmp/jailbreakd.pid");

    kernel_base = getCachedOffset(@"KernelBase");
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    
    kernprocaddr = getCachedOffset(@"KernProcAddr");
    offset_zonemap = getCachedOffset(@"ZoneMapOffset");
    
    offset_vnode_put = getCachedOffset(@"vnode_put");
    offset_vnode_lookup = getCachedOffset(@"vnode_lookup");
    offset_vfs_context_current = getCachedOffset(@"vfs_context_current");
    
    offset_add_ret_gadget = getCachedOffset(@"add_x0_x0_0x40_ret");
    offset_osboolean_true = getCachedOffset(@"OSBoolean_True");
    offset_osboolean_false = getCachedOffset(@"OSBoolean_False");
    offset_osunserializexml = getCachedOffset(@"osunserializexml");
    offset_smalloc = getCachedOffset(@"Smalloc");
    offset_kernel_task = getCachedOffset(@"KernelTask");
    offset_paciza_pointer__l2tp_domain_module_start = getCachedOffset(@"P2Start");
    offset_paciza_pointer__l2tp_domain_module_stop = getCachedOffset(@"P2Stop");
    offset_l2tp_domain_inited = getCachedOffset(@"L2DI");
    offset_sysctl__net_ppp_l2tp = getCachedOffset(@"CTL2");
    offset_sysctl_unregister_oid = getCachedOffset(@"CTLUO");
    offset_mov_x0_x4__br_x5 = getCachedOffset(@"Mx0");
    offset_mov_x9_x0__br_x1 = getCachedOffset(@"Mx9");
    offset_mov_x10_x3__br_x6 = getCachedOffset(@"Mx10");
    offset_kernel_forge_pacia_gadget = getCachedOffset(@"KFPG");
    offset_IOUserClient__vtable = getCachedOffset(@"IOUserClient__vtable");
    offset_IORegistryEntry__getRegistryEntryID = getCachedOffset(@"IORegistryEntry__getRegistryEntryID");
    offset_proc_rele = getCachedOffset(@"proc_rele");
    
    // tfp0, patchfinder, kexecute
    err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
    if (err != KERN_SUCCESS) {
        DEBUGLOG(true, "host_get_special_port 4: %s", mach_error_string(err));
        return -1;
    }
    DEBUGLOG(true, "tfp0: %x", tfp0);
    
    init_kexecute();
    
    queue = dispatch_queue_create("jailbreakd.queue", NULL);
    
    // Set up mach stuff
    mach_port_t server_port;
    if ((err = bootstrap_check_in(bootstrap_port, "ziyou.jailbreakd", &server_port))) {
        DEBUGLOG(true, "Failed to check in: %s", mach_error_string(err));
        return -1;
    }
    
    dispatch_source_t server = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, server_port, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(server, ^{
        dispatch_mig_server(server, jbd_jailbreak_daemon_subsystem.maxsize, jailbreak_daemon_server);
    });
    dispatch_resume(server);
    
    // Now ready for connections!
    DEBUGLOG(true, "mach server now running!");
    
    FILE *fd = fopen("/var/tmp/jailbreakd.pid", "w");
    fprintf(fd, "%d\n", getpid());
    fclose(fd);
    
    // Start accepting connections
    // This will block exec
    dispatch_main();
    
    return 0;
}
