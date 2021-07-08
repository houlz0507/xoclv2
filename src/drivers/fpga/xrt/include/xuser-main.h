/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Xilinx, Inc.
 *
 * Authors:
 *      Lizhi Hou <lizhih@xilinx.com>
 */

#ifndef _XUSER_MAIN_H_
#define _XUSER_MAIN_H_

#include <linux/interrupt.h>
#include "xleaf.h"

enum xrt_user_main_leaf_cmd {
	XRT_USER_MAIN_CONFIG_INTERRUPT = XRT_XLEAF_CUSTOM_BASE, /* See comments in xleaf.h */
};

struct xrt_user_main_config_intr {
	u32 index;
	irq_handler_t handler;
};

#endif /* _XUSER_MAIN_H_ */
