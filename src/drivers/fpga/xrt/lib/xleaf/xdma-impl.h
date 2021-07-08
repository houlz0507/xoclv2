/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Xilinx, Inc.
 *
 * Authors:
 *      Lizhi Hou <lizhih@xilinx.com>
 */

/* maximum number of channel */
#define XDMA_MAX_CHANNEL_NUM		16
#define XDMA_MAX_DESC_SETS		128

#define XDMA_SUBSYSTEM_ID		0x1fc
#define XDMA_DESC_MAGIC			0xad4b0000

/*
 * The registers must be accessed using 32-bit (PCI DWORD) read/writes.
 * XDMA spec:
 * https://www.xilinx.com/support/documentation/ip_documentation/xdma/v4_1/pg195-pcie-dma.pdf
 *
 * H2C: host to channel. C2H: channel to host
 */
#define XDMA_TARGET_RANGE		0x1000
enum {
	XDMA_TARGET_H2C_CHANNEL,
	XDMA_TARGET_C2H_CHANNEL,
	XDMA_TARGET_IRQ,
	XDMA_TARGET_CONFIG,
	XDMA_TARGET_H2C_DMA,
	XDMA_TARGET_C2H_DMA,
	XDMA_TARGET_COMMON_DMA,
	XDMA_TARGET_MSIX = 0x8,
};

/* maximum amount of register space to map */
#define XDMA_MAX_REGISTER_RANGE		(XDMA_TARGET_RANGE * XDMA_TARGET_MSIX)

/*
 * channel registers
 * w1s: Write 1 to Set
 * w1c: Write 1 to Clear
 */
#define XDMA_CHANNEL_RANGE		0x100
#define XDMA_CHANNEL_IDENTIFIER(base)	(base)
#define XDMA_CHANNEL_CONTROL(base)	((base) + 0x4)
#define XDMA_CHANNEL_CONTROL_W1S(base)	((base) + 0x8)
#define XDMA_CHANNEL_CONTROL_W1C(base)	((base) + 0xc)
#define XDMA_CHANNEL_INTERRUPT_EN(base)	((base) + 0x90)

#define XDMA_GET_SUBSYSTEM_ID(identifier)	(((identifier) & 0xfff00000) >> 20)
#define XDMA_GET_CHANNEL_ID(identifier)		(((identifier) & 0xf00) >> 8)
#define XDMA_GET_CHANNEL_TARGET(identifier)	(((identifier) & 0xf0000) >> 16)
#define XDMA_IS_STREAM(identifier)		(((identifier) & 0x80000) != 0)

/*
 * bits of channel control register
 */
#define XDMA_CTRL_RUN_STOP			(1UL << 0)
#define XDMA_CTRL_NON_INCR_ADDR			(1UL << 25)
#define XDMA_CTRL_POLL_MODE_WB			(1UL << 26)

/*
 * bits of interrupt enable register
 */
#define XDMA_IE_DESC_STOPPED		(1UL << 1)
#define XDMA_IE_DESC_COMPLETED		(1UL << 2)
#define XDMA_IE_DESC_ALIGN_MISMATCH	(1UL << 3)
#define XDMA_IE_MAGIC_STOPPED		(1UL << 4)
#define XDMA_IE_IDLE_STOPPED		(1UL << 6)
#define XDMA_IE_READ_ERROR		(0x1fUL << 9)
#define XDMA_IE_DESC_ERROR		(0x1fUL << 19)

#define XDMA_IE_DEFAULT		(XDMA_IE_DESC_ALIGN_MISMATCH | XDMA_IE_DESC_COMPLETED |	\
				 XDMA_IE_MAGIC_STOPPED | XDMA_IE_READ_ERROR |		\
				 XDMA_IE_DESC_ERROR | XDMA_IE_DESC_STOPPED)

/*
 * Descriptor for a single contiguous memory block transfer.
 *
 * Multiple descriptors are linked by means of the next pointer. An additional
 * extra adjacent number gives the amount of extra contiguous descriptors.
 */
struct xdma_desc {
	__le32 control;
	__le32 bytes;		/* transfer length in bytes */
	__le32 src_addr_lo;	/* source address (low 32-bit) */
	__le32 src_addr_hi;	/* source address (high 32-bit) */
	__le32 dst_addr_lo;	/* destination address (low 32-bit) */
	__le32 dst_addr_hi;	/* destination address (high 32-bit) */
	/*
	 * next descriptor in the single-linked list of descriptors;
	 * this is the PCIe (bus) address of the next descriptor in the
	 * root complex memory
	 */
	__le32 next_lo;		/* next desc address (low 32-bit) */
	__le32 next_hi;		/* next desc address (high 32-bit) */
} __packed;

#define XDMA_DMA_H(addr) (addr >> 32)
#define XDMA_DMA_L(addr) (addr & 0xffffffffUL)
