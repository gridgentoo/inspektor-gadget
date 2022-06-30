/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILETOP_H
#define __FILETOP_H

#define PATH_MAX	4096
#define TASK_COMM_LEN	16

enum op {
	READ,
	WRITE,
};

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	__u64 reads;
	__u64 read_bytes;
	__u64 writes;
	__u64 write_bytes;
	__u32 pid;
	__u32 tid;
	__u64 mntns_id;
	char filename[PATH_MAX];
	char comm[TASK_COMM_LEN];
	char type_;
};

// workaround to avoid reflection issue (non exported member ...)
struct file_id_pub {
	__u64 Inode;
	__u32 Dev;
	__u32 Pid;
	__u32 Tid;
};

struct file_stat_pub {
	__u64 Reads;
	__u64 Read_bytes;
	__u64 Writes;
	__u64 Write_bytes;
	__u32 Pid;
	__u32 Tid;
	__u64 Mntns_id;
	char Filename[PATH_MAX];
	char Comm[TASK_COMM_LEN];
	char Type_;
};


#endif /* __FILETOP_H */
