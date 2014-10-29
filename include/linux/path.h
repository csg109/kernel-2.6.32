#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

struct path {
	struct vfsmount *mnt; 	/* �����ļ�ϵͳ����Ϣ */
	struct dentry *dentry; 	/* �ļ�����inode֮��Ĺ��� */
};

extern void path_get(struct path *);
extern void path_put(struct path *);

#endif  /* _LINUX_PATH_H */
