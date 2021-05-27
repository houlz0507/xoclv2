// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx Alveo FPGA devctl Driver
 *
 * Copyright (C) 2020-2021 Xilinx, Inc.
 *
 * Authors:
 *      Lizhi Hou<Lizhi.Hou@xilinx.com>
 */

#include <linux/mod_devicetable.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/regmap.h>
#include <linux/io.h>
#include "metadata.h"
#include "xleaf.h"

#define XRT_XDMA "xrt_xdma"

XRT_DEFINE_REGMAP_CONFIG(xdma_regmap_config);

struct xrt_xdma {
	struct xrt_device	*xdev;
	struct regmap		*regmap;
	struct mutex		xdma_lock; /* xdma lock */
};

static int xdma_config_pci(struct xrt_xdma *xdma)
{
	struct xrt_root_config_pci config = { 0 };
	int ret;

	config.xpicp_opcode = XUSER_CLEAR_INTERRUPT;
	ret = xleaf_config_pci(xdma->xdev, &config);
	if (ret)
		goto failed;

	config.xpicp_opcode = 


	xleaf_root
}

static int xrt_xdma_probe(struct xrt_device *xdev)
{
	struct xrt_xdma *xdma = NULL;
	void __iomem *base = NULL;
	struct resource *res;
	int ret;

	xdma = devm_kzalloc(&xdev->dev, sizeof(*xdma), GFP_KERNEL);
	if (!xdma)
		return -ENOMEM;
	xdma->xdev = xdev;
	xrt_set_drvdata(xdev, xdma);

	xrt_info(xdev, "probing...");
	res = xrt_get_resource(xdev, IORESOURCE_MEM, 0);
	if (!res) {
		xrt_err(xdev, "Empty resource 0");
		ret = -EINVAL;
		goto failed;
	}

	base = devm_ioremap_resource(&xdev->dev, res);
	if (IS_ERR(base)) {
		xrt_err(xdev, "map base iomem failed");
		ret = PTR_ERR(base);
		goto failed;
	}

	xdma->regmap = devm_regmap_init_mmio(&xdev->dev, base, &xdma_regmap_config);
	if (IS_ERR(xdma->regmap)) {
		xrt_err(xdev, "regmap %pR failed", res);
		ret = PTR_ERR(xdma->regmap);
		goto failed;
	}

	mutex_init(&xdma->xdma_lock);

	ret = xdma_config_pci(xdma);
	if (ret)
		goto failed;

	return 0;

failed:
	return ret;
}

static struct xrt_dev_endpoints xrt_xdma_endpoints[] = {
	{
		.xse_names = (struct xrt_dev_ep_names[]) {
			{ .ep_name = XRT_MD_NODE_XDMA },
			{NULL},
		},
		.xse_min_ep = 1,
	},
	{ 0 },
};

static struct xrt_driver xrt_xdma_driver = {
	.driver = {
		.name = XRT_XDMA,
	},
	.subdev_id = XRT_SUBDEV_XDMA,
	.endpoints = xrt_xdma_endpoints,
	.probe = xrt_xdma_probe,
	.remove = xrt_xdma_remove,
	.leaf_call = xrt_xdma_leaf_call,
};

XRT_LEAF_INIT_FINI_FUNC(xdma);
