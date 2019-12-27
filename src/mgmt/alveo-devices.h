// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Xilinx, Inc. All rights reserved.
 *
 * Authors: sonal.santan@xilinx.com
 */

#ifndef	_XMGMT_ALVEO_DEVICES_H_
#define	_XMGMT_ALVEO_DEVICES_H_

#define	MGMTPF		0
#define	USERPF		1

#if PF == MGMTPF
#define SUBDEV_SUFFIX	".m"
#elif PF == USERPF
#define SUBDEV_SUFFIX	".u"
#endif

#define XOCL_FEATURE_ROM	"rom"
#define XOCL_IORES0		"iores0"
#define XOCL_IORES1		"iores1"
#define XOCL_IORES2		"iores2"
#define XOCL_XDMA		"dma.xdma"
#define XOCL_QDMA		"dma.qdma"
#define XOCL_MB_SCHEDULER	"mb_scheduler"
#define XOCL_XVC_PUB		"xvc_pub"
#define XOCL_XVC_PRI		"xvc_pri"
#define XOCL_NIFD_PRI		"nifd_pri"
#define XOCL_SYSMON		"sysmon"
#define XOCL_FIREWALL		"firewall"
#define	XOCL_MB			"microblaze"
#define	XOCL_PS			"processor_system"
#define	XOCL_XIIC		"xiic"
#define	XOCL_MAILBOX		"mailbox"
#define	XOCL_ICAP		"icap"
#define	XOCL_AXIGATE		"axigate"
#define	XOCL_MIG		"mig"
#define	XOCL_XMC		"xmc"
#define	XOCL_DNA		"dna"
#define	XOCL_FMGR		"fmgr"
#define	XOCL_FLASH		"flash"
#define XOCL_DMA_MSIX		"dma_msix"
#define	XOCL_MAILBOX_VERSAL	"mailbox_versal"
#define XOCL_ERT		"ert"

#define XOCL_DEVNAME(str)	str SUBDEV_SUFFIX

enum subdev_id {
	XOCL_SUBDEV_FEATURE_ROM,
	XOCL_SUBDEV_AXIGATE,
	XOCL_SUBDEV_DMA,
	XOCL_SUBDEV_IORES,
	XOCL_SUBDEV_FLASH,
	XOCL_SUBDEV_MB_SCHEDULER,
	XOCL_SUBDEV_XVC_PUB,
	XOCL_SUBDEV_XVC_PRI,
	XOCL_SUBDEV_NIFD_PRI,
	XOCL_SUBDEV_SYSMON,
	XOCL_SUBDEV_AF,
	XOCL_SUBDEV_MIG,
	XOCL_SUBDEV_MB,
	XOCL_SUBDEV_PS,
	XOCL_SUBDEV_XIIC,
	XOCL_SUBDEV_MAILBOX,
	XOCL_SUBDEV_ICAP,
	XOCL_SUBDEV_DNA,
	XOCL_SUBDEV_FMGR,
	XOCL_SUBDEV_MIG_HBM,
	XOCL_SUBDEV_MAILBOX_VERSAL,
	XOCL_SUBDEV_OSPI_VERSAL,
	XOCL_SUBDEV_NUM
};

enum region_id {
	XOCL_REGION_STATIC,
	XOCL_REGION_BLD,
	XOCL_REGION_PRP,
	XOCL_REGION_URP,
	XOCL_REGION_LEGACYRP,
	XOCL_REGION_MAX,
};

#define XOCL_STATIC           "STATIC"
#define	XOCL_REGION_BLD       "BLD"
#define	XOCL_REGION_PRP       "PRP"
#define	XOCL_REGION_URP       "URP"
#define	XOCL_REGION_LEGACYR   "LEGACYPR"


struct xocl_subdev_info {
	enum subdev_id		id;
	const char	       *name;
	struct resource	       *res;
	int			num_res;
	void		       *priv_data;
	int			data_len;
	bool			multi_inst;
	int			level;
	char		       *bar_idx;
	int			dyn_ip;
	const char	       *override_name;
	int			override_idx;
};

struct xmgmt_subdev_ops {
	int (*init)(struct platform_device *pdev, const struct xocl_subdev_info *detail);
	void (*uinit)(struct platform_device *pdev);
	long (*ioctl)(struct platform_device *pdev, unsigned int cmd, unsigned long arg);
};

struct xmgmt_subdev_core {
	enum subdev_id                id;
	const char	             *name;
	const struct xocl_subdev_ops *ops;
	void                         *sdata;
};

struct xmgmt_region {
	struct xmgmt_dev       *lro;
	enum region_id          id;
	struct platform_device *region;
	int                     child_count;
	struct platform_device *children[1];
};

#endif