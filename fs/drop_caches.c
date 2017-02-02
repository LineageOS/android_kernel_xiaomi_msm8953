/*
 * Implement the manual drop-all-pagecache function
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/fb.h>
#include <linux/delay.h>
#include "internal.h"

/* A global variable is a bit ugly, but it keeps the code simple */
int sysctl_drop_caches;

void drop_pagecache_sb(struct super_block *sb, void *unused)
{
	struct inode *inode, *toput_inode = NULL;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);
		invalidate_mapping_pages(inode->i_mapping, 0, -1);
		iput(toput_inode);
		toput_inode = inode;
		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);
	iput(toput_inode);
}

static void drop_slab(void)
{
	int nr_objects;
	struct shrink_control shrink = {
		.gfp_mask = GFP_KERNEL,
	};

	nodes_setall(shrink.nodes_to_scan);
	do {
		nr_objects = shrink_slab(&shrink, 1000, 1000);
	} while (nr_objects > 10);
}

int drop_caches_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret)
		return ret;
	if (write) {
		static int stfu;

		if (sysctl_drop_caches & 1) {
			iterate_supers(drop_pagecache_sb, NULL);
			count_vm_event(DROP_PAGECACHE);
		}
		if (sysctl_drop_caches & 2) {
			drop_slab();
			count_vm_event(DROP_SLAB);
		}
		if (!stfu) {
			pr_info("%s (%d): drop_caches: %d\n",
				current->comm, task_pid_nr(current),
				sysctl_drop_caches);
		}
		stfu |= sysctl_drop_caches & 4;
	}
	return 0;
}

static void drop_caches_suspend(struct work_struct *work);
static DECLARE_WORK(drop_caches_suspend_work, drop_caches_suspend);

static void drop_caches_suspend(struct work_struct *work)
{
	/* sleep for 200ms */
	msleep(200);
	/* sync */
	emergency_sync();
	/* echo "3" > /proc/sys/vm/drop_caches */
	iterate_supers(drop_pagecache_sb, NULL);
        drop_slab();
}

static int fb_notifier(struct notifier_block *self,
			unsigned long event, void *data)
{
	struct fb_event *evdata = (struct fb_event *)data;

	if ((event == FB_EVENT_BLANK) && evdata && evdata->data) {
		int blank = *(int *)evdata->data;

		if (blank == FB_BLANK_POWERDOWN) {
			schedule_work_on(0, &drop_caches_suspend_work);
			return NOTIFY_OK;
		}
		return NOTIFY_OK;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fb_notifier_block = {
	.notifier_call = fb_notifier,
	.priority = -1,
};

static int __init drop_caches_init(void)
{
	fb_register_client(&fb_notifier_block);
	return 0;
}
late_initcall(drop_caches_init);
