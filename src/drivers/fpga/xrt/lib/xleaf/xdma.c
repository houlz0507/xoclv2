// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx Alveo FPGA devctl Driver
 *
 * Copyright (C) 2020-2021 Xilinx, Inc.
 *
 * Authors:
 *      Lizhi Hou<Lizhi.Hou@xilinx.com>
 */

#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/regmap.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include "metadata.h"
#include "xleaf.h"
#include "xdma-impl.h"

#define XRT_XDMA "xrt_xdma"
#define XRT_XDMA_CHANNEL_H2C "xrt_xdma_channel_h2c"
#define XRT_XDMA_CHANNEL_C2H "xrt_xdma_channel_c2h"

static unsigned int xrt_xdma_desc_set_depth = 32;
module_param(xrt_xdma_desc_set_depth, uint, 0644);
MODULE_PARM_DESC(xrt_xdma_desc_set_depth, "Supported Values 16, 32, 64, 128, default is 32");

XRT_DEFINE_REGMAP_CONFIG(xdma_regmap_config);

struct xdma_channel {
	u32			base;
	u32			dma_base;
	u32			chan_id;
	u32			cpu_idx;
	struct xdma_desc	*desc;
	u32			desc_num;
	dma_addr_t		desc_bus;
	struct work_struct	work;
	bool			active;
};

struct xrt_xdma {
	struct xrt_device	*xdev;
	struct regmap		*regmap;
	struct mutex		xdma_lock; /* xdma lock */
	struct xdma_channel	h2c_channel[XDMA_MAX_CHANNEL_NUM];
	u32			h2c_channel_num;
	struct xdma_channel	c2h_channel[XDMA_MAX_CHANNEL_NUM];
	u32			c2h_channel_num;
};

static irqreturn_t xdma_channel_irq_handler(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static void xdma_channel_service(struct work_struct *work)
{
}

static void xdma_free_channel_resource(struct xrt_xdma *xdma, struct xdma_channel *channel)
{
	struct xrt_root_dma_buffer_req req = { 0 };
	struct xrt_device *xdev = xdma->xdev;

	if (!channel->desc || !channel->desc_bus) {
		xrt_err(xdev, "desc of desc_bus is null");
		return;
	}

	req.xpidbr_coherent = true;
	req.xpidbr_size = channel->desc_num * sizeof(struct xdma_desc);
	req.xpidbr_buf = channel->desc;
	req.xpidbr_dma_handle = channel->desc_bus;

	xrt_subdev_root_request(xdev, XRT_ROOT_FREE_DMA_BUFFER, &req);
}

static int xdma_alloc_channel_resource(struct xrt_xdma *xdma, struct xdma_channel *channel)
{
	struct xrt_root_dma_buffer_req req = { 0 }; 
	struct xrt_device *xdev = xdma->xdev;
	dma_addr_t desc_bus;
	u32 desc_num;
	int ret, i;

	desc_num = XDMA_MAX_DESC_SETS * xrt_xdma_desc_set_depth;
	req.xpidbr_coherent = true;
	req.xpidbr_size = desc_num * sizeof(struct xdma_desc);
	ret = xrt_subdev_root_request(xdev, XRT_ROOT_ALLOC_DMA_BUFFER, &req);
	if (ret) {
		xrt_err(xdev, "failed to alloc dma buffer: %d", ret);
		return ret;
	}

	channel->desc = (struct xdma_desc *)req.xpidbr_buf;
	channel->desc_bus = req.xpidbr_dma_handle;
	channel->desc_num = desc_num;
	desc_bus = channel->desc_bus;
	for (i = 0; i < desc_num; i++) {
		desc_bus += sizeof(struct xdma_desc);

		channel->desc[i].next_lo = cpu_to_le32(XDMA_DMA_L(desc_bus));
		channel->desc[i].next_hi = cpu_to_le32(XDMA_DMA_H(desc_bus));
		channel->desc[i].control = cpu_to_le32(XDMA_DESC_MAGIC);
	}
	channel->desc[i - 1].next_lo = 0;
	channel->desc[i - 1].next_hi = 0;

	return 0;
}

static int xdma_probe_channel(struct xrt_xdma *xdma, u32 base)
{
	struct xrt_root_irq_req req = { 0 };
	struct xdma_channel *channel;
	u32 identifier, *index, type;
	int ret;

	ret = regmap_read(xdma->regmap, XDMA_CHANNEL_IDENTIFIER(base), &identifier);
	if (ret) {
		xrt_err(xdma->xdev, "failed to read identifier: %d", ret);
		return ret;
	}

	if (XDMA_GET_SUBSYSTEM_ID(identifier) != XDMA_SUBSYSTEM_ID)
		return -EINVAL;

	type = XDMA_GET_CHANNEL_TARGET(identifier);
	if (type == XDMA_TARGET_H2C_CHANNEL) {
		index = &xdma->h2c_channel_num;
		channel = &xdma->h2c_channel[*index];
	} else if (type == XDMA_TARGET_C2H_CHANNEL) {
		index = &xdma->c2h_channel_num;
		channel = &xdma->c2h_channel[*index];
	} else
		return -EINVAL;

	if (XDMA_IS_STREAM(identifier))
		return -EOPNOTSUPP;

	channel->chan_id = XDMA_GET_CHANNEL_ID(identifier);

	/* channel id should match index */
	if (channel->chan_id != *index)
		return -EINVAL;

	channel->base = base;
	channel->dma_base = base + XDMA_TARGET_RANGE * XDMA_TARGET_H2C_DMA;
	channel->cpu_idx = *index % num_online_cpus();

	INIT_WORK(&channel->work, xdma_channel_service);
	ret = xdma_alloc_channel_resource(xdma, channel);
	if (ret)
		return ret;

	ret = regmap_write(xdma->regmap, XDMA_CHANNEL_CONTROL_W1C(base),
			   XDMA_CTRL_NON_INCR_ADDR);
	if (ret) {
		xrt_err(xdma->xdev, "failed to clear non_incr_addr bit");
		goto failed;
	}

	ret = regmap_write(xdma->regmap, XDMA_CHANNEL_INTERRUPT_EN(base),
			   XDMA_IE_DEFAULT);
	if (ret) {
		xrt_err(xdma->xdev, "failed to set interrupt enable reg");
		goto failed;
	}

	req.xpiir_handler = xdma_channel_irq_handler;
	req.xpiir_dev_id = channel;
	req.xpiir_vec_idx = channel->chan_id;
	if (type == XDMA_TARGET_H2C_CHANNEL)
		req.xpiir_name = XRT_XDMA_CHANNEL_H2C;
	else
		req.xpiir_name = XRT_XDMA_CHANNEL_C2H;

	ret = xrt_subdev_root_request(xdma->xdev, XRT_ROOT_REQUEST_IRQ, &req);
	if (ret) {
		xrt_err(xdma->xdev, "request h2c interrupt failed: %d", ret);
		goto failed;
	}
	channel->active = true;

	return 0;

failed:
	xdma_free_channel_resource(xdma, channel);
	return ret;
}

static void xdma_cleanup_channels(struct xrt_xdma *xdma)
{
}

static int xdma_init_channels(struct xrt_xdma *xdma)
{
	struct xrt_root_irq_req req = { 0 };
	int i, ret;

	for (i = 0; i < XDMA_MAX_CHANNEL_NUM * 2; i++) {
		ret = xdma_probe_channel(xdma, XDMA_CHANNEL_RANGE * i);
		if (ret)
			break;
	}
	if (!xdma->h2c_channel_num) {
		xrt_err(xdma->xdev, "Not find h2c channel");
		goto failed;
	}
	if (!xdma->c2h_channel_num) {
		xrt_err(xdma->xdev, "Not find c2h channel");
		goto failed;
	}

	return 0;

failed:
	xdma_cleanup_channels(xdma);
	return ret;
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

	xdma_regmap_config.max_register = XDMA_MAX_REGISTER;
	xdma->regmap = devm_regmap_init_mmio(&xdev->dev, base, &xdma_regmap_config);
	if (IS_ERR(xdma->regmap)) {
		xrt_err(xdev, "regmap %pR failed", res);
		ret = PTR_ERR(xdma->regmap);
		goto failed;
	}

	mutex_init(&xdma->xdma_lock);

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
