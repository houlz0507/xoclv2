// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx Alveo FPGA MGMT PF entry point driver
 *
 * Copyright (C) 2020 Xilinx, Inc.
 *
 * Authors:
 *	Sonal Santan <sonals@xilinx.com>
 */

#include <linux/delay.h>
#include "xocl-subdev.h"
#include "uapi/mgmt-ioctl.h"

#define	XOCL_MGMT "xocl_mgmt"

struct xocl_mgmt {
	struct platform_device *pdev;
	struct platform_device *leaf;
	void *evt_hdl;
	struct mutex busy_mutex;
};

static bool xocl_mgmt_leaf_match(enum xocl_subdev_id id,
	struct platform_device *pdev, void *arg)
{
	int myid = (int)(uintptr_t)arg;
	return id == XOCL_SUBDEV_MGMT && pdev->id != myid;
}

static ssize_t hold_store(struct device *dev,
	struct device_attribute *da, const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct xocl_mgmt *xt = platform_get_drvdata(pdev);
	struct platform_device *leaf;

	leaf = xocl_subdev_get_leaf(pdev, xocl_mgmt_leaf_match,
		(void *)(uintptr_t)pdev->id);
	if (leaf)
		xt->leaf = leaf;
	return count;
}
static DEVICE_ATTR_WO(hold);

static ssize_t release_store(struct device *dev,
	struct device_attribute *da, const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct xocl_mgmt *xt = platform_get_drvdata(pdev);

	if (xt->leaf)
		(void) xocl_subdev_put_leaf(pdev, xt->leaf);
	return count;
}
static DEVICE_ATTR_WO(release);

static struct attribute *xocl_mgmt_attrs[] = {
	&dev_attr_hold.attr,
	&dev_attr_release.attr,
	NULL,
};

static const struct attribute_group xocl_mgmt_attrgroup = {
	.attrs = xocl_mgmt_attrs,
};

static int xocl_mgmt_event_cb(struct platform_device *pdev,
	enum xocl_events evt, enum xocl_subdev_id id, int instance)
{
	struct platform_device *leaf;

	xocl_info(pdev, "event %d for (%d, %d)", evt, id, instance);

	switch (evt) {
	case XOCL_EVENT_POST_CREATION:
		break;
	default:
		return 0;
	}

	leaf = xocl_subdev_get_leaf_by_id(pdev, id, instance);
	if (leaf) {
		(void) xocl_subdev_ioctl(leaf, 1, NULL);
		(void) xocl_subdev_put_leaf(pdev, leaf);
	}
	return 0;
}

static int xocl_mgmt_probe(struct platform_device *pdev)
{
	struct xocl_mgmt *xt;

	xocl_info(pdev, "probing...");

	xt = devm_kzalloc(DEV(pdev), sizeof(*xt), GFP_KERNEL);
	if (!xt)
		return -ENOMEM;

	xt->pdev = pdev;
	platform_set_drvdata(pdev, xt);
	mutex_init(&xt->busy_mutex);
	/* Ready to handle req thru sysfs nodes. */
	if (sysfs_create_group(&DEV(pdev)->kobj, &xocl_mgmt_attrgroup))
		xocl_err(pdev, "failed to create sysfs group");

	/* Ready to handle req thru cdev. */
	(void) xocl_devnode_create(pdev, "xmgmt", NULL);

	/* Add event callback to wait for the peer instance. */
	xt->evt_hdl = xocl_subdev_add_event_cb(pdev, xocl_mgmt_leaf_match,
		(void *)(uintptr_t)pdev->id, xocl_mgmt_event_cb);

	/* After we return here, we'll get inter-leaf calls. */
	return 0;
}

static int xocl_mgmt_remove(struct platform_device *pdev)
{
	int ret;
	struct xocl_mgmt *xt = platform_get_drvdata(pdev);

	/* By now, partition driver should prevent any inter-leaf call. */

	xocl_info(pdev, "leaving...");

	(void) xocl_subdev_remove_event_cb(pdev, xt->evt_hdl);

	ret = xocl_devnode_destroy(pdev);
	if (ret)
		return ret;
	/* By now, no more access thru cdev. */

	(void) sysfs_remove_group(&DEV(pdev)->kobj, &xocl_mgmt_attrgroup);
	/* By now, no more access thru sysfs nodes. */

	/* Clean up can safely be done now. */
	return 0;
}

static int
xocl_mgmt_leaf_ioctl(struct platform_device *pdev, u32 cmd, void *arg)
{
	xocl_info(pdev, "handling IOCTL cmd: %d", cmd);
	return 0;
}

static int xocl_mgmt_open(struct inode *inode, struct file *file)
{
	struct platform_device *pdev = xocl_devnode_open(inode);

	/* Device may have gone already when we get here. */
	if (!pdev)
		return -ENODEV;

	xocl_info(pdev, "opened");
	file->private_data = platform_get_drvdata(pdev);
	return 0;
}

static ssize_t
xocl_mgmt_read(struct file *file, char __user *ubuf, size_t n, loff_t *off)
{
	int i;
	struct xocl_mgmt *xt = file->private_data;

	for (i = 0; i < 10; i++) {
		xocl_info(xt->pdev, "reading...");
		ssleep(1);
	}
	return 0;
}

static int xocl_mgmt_close(struct inode *inode, struct file *file)
{
	struct xocl_mgmt *xt = file->private_data;

	xocl_devnode_close(inode);

	xocl_info(xt->pdev, "closed");
	return 0;
}

static long xocl_mgmt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long result = 0;
	struct xocl_mgmt *xt = filp->private_data;

	BUG_ON(!xt);

	if (_IOC_TYPE(cmd) != XCLMGMT_IOC_MAGIC)
		return -ENOTTY;

	if (result)
		return -EFAULT;

	mutex_lock(&xt->busy_mutex);

	xocl_info(xt->pdev, "ioctl cmd %d, arg %ld", cmd, arg);
	switch (cmd) {
	case XCLMGMT_IOCINFO:
		break;
	case XCLMGMT_IOCICAPDOWNLOAD_AXLF:
		break;
	case XCLMGMT_IOCFREQSCALE:
		break;
	default:
		result = -ENOTTY;
	}
	mutex_unlock(&xt->busy_mutex);
	return result;
}


struct xocl_subdev_drvdata xocl_mgmt_data = {
	.xsd_dev_ops = {
		.xsd_ioctl = xocl_mgmt_leaf_ioctl,
	},
	.xsd_file_ops = {
		.xsf_ops = {
			.owner = THIS_MODULE,
			.open = xocl_mgmt_open,
			.release = xocl_mgmt_close,
			.read = xocl_mgmt_read,
			.unlocked_ioctl = xocl_mgmt_ioctl,
		},
	},
};

static const struct platform_device_id xocl_mgmt_id_table[] = {
	{ XOCL_MGMT, (kernel_ulong_t)&xocl_mgmt_data },
	{ },
};

struct platform_driver xocl_mgmt_driver = {
	.driver	= {
		.name    = XOCL_MGMT,
	},
	.probe   = xocl_mgmt_probe,
	.remove  = xocl_mgmt_remove,
	.id_table = xocl_mgmt_id_table,
};
