/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

struct args_t {
	const char *fname;
	int flags;
};

struct event {
	__u64 timestamp;
	/* user terminology for pid: */
	__u32 pid;
	__u32 uid;
	__u64 mntns_id;
	int ret;
	int flags;
	__u8 comm[TASK_COMM_LEN];
	__u8 fname[NAME_MAX];
};

#endif /* __OPENSNOOP_H */
