// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx Alveo FPGA USER PF entry point driver
 *
 * Copyright (C) 2021 Xilinx, Inc.
 *
 * Authors:
 *      Lizhi Hou <lizhih@xilinx.com>
 */

#include "subdev_id.h"
#include "metadata.h"
#include "xdevice.h"
#include "xleaf.h"
#include "xuser.h"

#define XUSER_MAIN "xuser_main"

struct xuser_main {
	struct xrt_device *xdev;
	char *firmware_dtb;
	int firmware_group_instance;
	void *mailbox_hdl;
};

/* logic uuid is the uuid uniquely identfy the partition */
static ssize_t logic_uuids_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return 0;
}
static DEVICE_ATTR_RO(logic_uuids);

static ssize_t interface_uuids_show(struct device *dev, struct device_attribute *da, char *buf)
{
        return 0;
}
static DEVICE_ATTR_RO(interface_uuids);

static struct attribute *xuser_main_attrs[] = {
	&dev_attr_logic_uuids.attr,
	&dev_attr_interface_uuids.attr,
	NULL,
};

static const struct attribute_group xuser_main_attrgroup = {
	.attrs = xuser_main_attrs,
};

static int xuser_refresh_firmware(struct xuser_main *xum)
{
	struct xrt_device *xdev = xum->xdev;
	char *dtb;
	int ret;

	ret = xuser_peer_get_metadata(xum->mailbox_hdl, &dtb);
	if (ret) {
		xrt_err(xdev, "failed to get metadata, ret %d", ret);
		return ret;
	}

	if (xum->firmware_group_instance != XRT_INVALID_DEVICE_INST) {
		ret = xleaf_destroy_group(xdev, xum->firmware_group_instance);
		if (ret) {
			xrt_err(xdev, "failed to remove current group %d, ret %d",
				xum->firmware_group_instance, ret);
			return ret;
		}
		xum->firmware_group_instance = XRT_INVALID_DEVICE_INST;

		WARN_ON(!xum->firmware_dtb);
		vfree(xum->firmware_dtb);
		xum->firmware_dtb = NULL;
	}

	WARN_ON(xum->firmware_dtb);
	if (dtb) {
		ret = xleaf_create_group(xdev, dtb);
		if (ret < 0) {
			xrt_err(xdev, "failed to create group, ret %d", ret);
			return ret;
		}
		xum->firmware_group_instance = ret;
		xum->firmware_dtb = dtb;
	}

	return 0;
}

static void xuser_main_event_cb(struct xrt_device *xdev, void *arg)
{
	struct xrt_event *evt = (struct xrt_event *)arg;
	struct xuser_main *xum = xrt_get_drvdata(xdev);
	enum xrt_events e = evt->xe_evt;
	enum xrt_subdev_id id;

	id = evt->xe_subdev.xevt_subdev_id;
	switch (e) {
	case XRT_EVENT_POST_CREATION:
		/* user driver finishes attaching, get its partition metadata */
		if (id == XRT_ROOT)
			xuser_refresh_firmware(xum);
		break;
	case XRT_EVENT_PEER_ONLINE:
		xuser_refresh_firmware(xum);
		break;
	default:
		xrt_dbg(xdev, "ignored event %d", e);
		break;
	}
}

static int xuser_main_probe(struct xrt_device *xdev)
{
	struct xuser_main *xum;

	xrt_info(xdev, "probing...");

	xum = devm_kzalloc(DEV(xdev), sizeof(*xum), GFP_KERNEL);
	if (!xum)
		return -ENOMEM;

	xum->xdev = xdev;
	xum->firmware_group_instance = XRT_INVALID_DEVICE_INST;
	xrt_set_drvdata(xdev, xum);
	xum->mailbox_hdl = xuser_mailbox_probe(xdev);

	/* Ready to handle req thru sysfs nodes. */
	if (sysfs_create_group(&DEV(xdev)->kobj, &xuser_main_attrgroup))
		xrt_err(xdev, "failed to create sysfs group");

	return 0;
}

static void xuser_main_remove(struct xrt_device *xdev)
{
	struct xuser_main *xum = xrt_get_drvdata(xdev);

	/* By now, group driver should prevent any inter-leaf call. */

	xrt_info(xdev, "leaving...");

	xuser_mailbox_remove(xum->mailbox_hdl);
	sysfs_remove_group(&DEV(xdev)->kobj, &xuser_main_attrgroup);
}

static int xuser_mainleaf_call(struct xrt_device *xdev, u32 cmd, void *arg)
{
	int ret = 0;

	switch (cmd) {
	case XRT_XLEAF_EVENT:
		xuser_mailbox_event_cb(xdev, arg);
		xuser_main_event_cb(xdev, arg);
		break;
	default:
		xrt_err(xdev, "unknown cmd: %d", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}

void *xuser_xdev2mailbox(struct xrt_device *xdev)
{
	struct xuser_main *xum = xrt_get_drvdata(xdev);

	return xum->mailbox_hdl;
}

static struct xrt_dev_endpoints xrt_user_main_endpoints[] = {
	{
		.xse_names = (struct xrt_dev_ep_names[]){
			{ .ep_name = XRT_MD_NODE_USER_MAIN },
			{ NULL },
		},
		.xse_min_ep = 1,
	},
	{ 0 },
};

static struct xrt_driver xuser_main_driver = {
	.driver = {
		.name = XUSER_MAIN,
	},
	.subdev_id = XRT_SUBDEV_USER_MAIN,
	.endpoints = xrt_user_main_endpoints,
	.probe = xuser_main_probe,
	.remove = xuser_main_remove,
	.leaf_call = xuser_mainleaf_call,
};

int xuser_register_leaf(void)
{
	return xrt_register_driver(&xuser_main_driver);
}

void xuser_unregister_leaf(void)
{
	xrt_unregister_driver(&xuser_main_driver);
}
