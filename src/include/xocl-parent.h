/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Xilinx, Inc.
 *
 * Authors:
 *	Cheng Zhen <maxz@xilinx.com>
 */

#ifndef	_XOCL_PARENT_H_
#define	_XOCL_PARENT_H_

#include "xocl-subdev.h"
#include "xocl-partition.h"

/*
 * Parent IOCTL calls.
 */
enum xocl_parent_ioctl_cmd {
	XOCL_PARENT_GET_LEAF = 0,
	XOCL_PARENT_PUT_LEAF,
	XOCL_PARENT_CREATE_PARTITION,
	XOCL_PARENT_REMOVE_PARTITION,
	XOCL_PARENT_ADD_EVENT_CB,
	XOCL_PARENT_REMOVE_EVENT_CB,
	XOCL_PARENT_BOARDCAST_EVENT,
	XOCL_PARENT_GET_HOLDERS,
	XOCL_PARENT_GET_BAR,
	XOCL_PARENT_HOT_RESET,
};

struct xocl_parent_ioctl_get_leaf {
	struct platform_device *xpigl_pdev; /* caller's pdev */
	xocl_subdev_match_t xpigl_match_cb;
	void *xpigl_match_arg;
	struct platform_device *xpigl_leaf; /* target leaf pdev */
};

struct xocl_parent_ioctl_put_leaf {
	struct platform_device *xpipl_pdev; /* caller's pdev */
	struct platform_device *xpipl_leaf; /* target's pdev */
};

struct xocl_parent_ioctl_evt_cb {
	struct platform_device *xevt_pdev; /* caller's pdev */
	xocl_subdev_match_t xevt_match_cb;
	void *xevt_match_arg;
	xocl_event_cb_t xevt_cb;
	void *xevt_hdl;
};

struct xocl_parent_ioctl_get_holders {
	struct platform_device *xpigh_pdev; /* caller's pdev */
	char *xpigh_holder_buf;
	size_t xpigh_holder_buf_len;
};

struct xocl_parent_ioctl_get_bar {
	void *xpigb_bar_addrs;
	ulong *xpigb_bar_len;
};

#endif	/* _XOCL_PARENT_H_ */
