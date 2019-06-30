//
//  vnode_utils.c
//  test
//
//  Created by Tanay Findley on 5/19/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include <stdio.h>
#include "vnode_utils.h"
#include "kern_utils.h"
#include "kexecute.h"
#include "kmem.h"

uint64_t _vfs_context() {
    static uint64_t vfs_context = 0;
    if (vfs_context == 0) {
        vfs_context = kexecute(offset_vfs_context_current, 1, 0, 0, 0, 0, 0, 0);
        vfs_context = zm_fix_addr(vfs_context);
    }
    return vfs_context;
}

int _vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context) {
    size_t len = strlen(path) + 1;
    uint64_t vnode = kalloc(sizeof(uint64_t));
    uint64_t ks = kalloc(len);
    kwrite(ks, path, len);
    int ret = (int)kexecute(offset_vnode_lookup, ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != ERR_SUCCESS) {
        return -1;
    }
    *vpp = rk64(vnode);
    kfree(ks, len);
    kfree(vnode, sizeof(uint64_t));
    return 0;
}

uint64_t vnodeForPath(const char *path) {
    uint64_t vfs_context = 0;
    uint64_t *vpp = NULL;
    uint64_t vnode = 0;
    vfs_context = _vfs_context();
    vpp = malloc(sizeof(uint64_t));
    if (vpp == NULL) {
        fprintf(stderr, "Failed to allocate memory.");
        goto out;
    }
    if (_vnode_lookup(path, O_RDONLY, vpp, vfs_context) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to get vnode at path \"%s\".", path);
        goto out;
    }
    vnode = *vpp;
    out:
    if (vpp != NULL) {
        free(vpp);
        vpp = NULL;
    }
    return vnode;
}

int _vnode_put(uint64_t vnode) {
    return (int)kexecute(offset_vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}
