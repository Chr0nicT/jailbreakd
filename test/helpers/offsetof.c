
#define offsetof_p_pid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x60) : (0x10)) // proc_t::p_pid
#define offsetof_task (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x10) : (0x18)) // proc_t::task
#define offsetof_p_svuid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x32) : (0x40)) // proc_t::svuid
#define offsetof_p_svgid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x36) : (0x44)) // proc_t::svgid
#define offsetof_p_ucred (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0xf8) : (0x100)) // proc_t::p_ucred
#define offsetof_p_csflags (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x290) : (0x2a8)) // proc_t::p_csflags
#define offsetof_itk_space (unsigned)((kCFCoreFoundationVersionNumber >= 1443.00) ? ((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x300) : (0x308)) : (0x300)) // task_t::itk_space
#define offsetof_ip_kobject (unsigned)(0x68) // ipc_port_t::ip_kobject
#define offsetof_p_textvp (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x230) : (0x248)) // proc_t::p_textvp
#define offsetof_ipc_space_is_table (unsigned)(0x20) // ipc_space::is_table?..

#define offsetof_ucred_cr_uid (unsigned)(0x18) // ucred::cr_uid
#define offsetof_ucred_cr_svuid (unsigned)(0x20) // ucred::cr_svuid
#define offsetof_ucred_cr_groups (unsigned)(0x28) // ucred::cr_groups
#define offsetof_ucred_cr_svgid (unsigned)(0x6c) // ucred::cr_svgid

#define offsetof_v_type (unsigned)(0x70) // vnode::v_type
#define offsetof_v_ubcinfo (unsigned)(0x78) // vnode::v_ubcinfo

#define offsetof_ubcinfo_csblobs (unsigned)(0x50) // ubc_info::csblobs

#define offsetof_csb_platform_binary (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0xA4) : (0xa8)) // cs_blob::csb_platform_binary

#define offsetof_t_flags (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x390) : (0x3a0)) // task::t_flags
