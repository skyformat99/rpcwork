/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __RPC_PROTO_H__
#define __RPC_PROTO_H__

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <stddef.h>

#define SD_PROTO_VER 0x02

/* This or later version supports trimming zero sectors from read response */
#define SD_PROTO_VER_TRIM_ZERO_SECTORS 0x02

#define SD_LISTEN_PORT 7000

#define SD_OP_EOFS_LOAD       0x01
#define SD_OP_EOFS_READ       0x02
#define SD_OP_EOFS_WRITE      0x03
#define SD_OP_EOFS_LOCAL_LOAD 0x04
#define SD_OP_EOFS_LOCAL_FLUSH 0x05
#define SD_OP_EOFS_LOCAL_DELETE 0x06
#define SD_OP_EOFS_CLEAN_NODE 0x07
#define SD_OP_EOFS_READ_DEPOSIT       0x08
#define SD_OP_EOFS_WRITE_DEPOSIT      0x09
#define SD_OP_EOFS_TRUNCATE_DEPOSIT      0x0A
#define SD_OP_EOFS_FLUSH_DEPOSIT 0x0B
#define SD_OP_EOFS_CLEAN_DEPOSIT 0x0C
#define SD_OP_EOFS_CLOSE_DEPOSIT 0x0D
#define SD_OP_EOFS_CREATE_RBD	 0x0E
#define SD_OP_EOFS_TRUNCATE_RBD	 0x0F
#define SD_OP_EOFS_READ_RBD      0x10
#define SD_OP_EOFS_WRITE_RBD     0x11
#define SD_OP_EOFS_DELETE_RBD	 0x12
#define SD_OP_EOFS_CREATE_SC	 0x13
#define SD_OP_EOFS_SET_TRUNCATE_INFO	 0x14


#define SD_OP_CS_OPEN       0x21
#define SD_OP_CS_READ       0x22
#define SD_OP_CS_WRITE      0x23
#define SD_OP_CS_FLUSH	    0x24
#define SD_OP_CS_UNLOAD     0x25
#define SD_OP_CS_LOAD       0x26
#define SD_OP_CS_COMMIT     0x27
#define SD_OP_CS_STAT       0x28

#define SD_OP_CS_CREATE_TEST     0x29
#define SD_OP_CS_DELETE_TEST     0x2A
#define SD_OP_CS_TRUNCATE_TEST	 0x2B   
#define SD_OP_CS_EXIST_TEST	     0x2C 


#define SD_OP_MDS_REGIST       0x30
#define SD_OP_MDS_WRITE        0x31
#define SD_OP_MDS_READ         0x32
#define SD_OP_MDS_LIST         0x33
#define SD_OP_MDS_HEARTBEAT    0x34
#define SD_OP_MDS_DROP_MASTER  0x35
#define SD_OP_MDS_MWRITE       0x36
#define SD_OP_MDS_REGION_SYNC  0x37
#define SD_OP_MDS_GROUP_UPDATE 0x38
#define SD_OP_MDS_REGION_ADD      0x39
#define SD_OP_MDS_REGION_DELETE   0x3A
#define SD_OP_MDS_REGION_UPDATE   0x3B
#define SD_OP_MDS_MDS_CTRL        0x3C
#define SD_OP_MDS_CACHE_CTRL      0x3D






#define SD_OP_SHOTDOWN         0xFF


/* macros in the SD_FLAG_CMD_XXX group are mutually exclusive */
#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02
#define SD_FLAG_CMD_CACHE    0x04
#define SD_FLAG_CMD_DIRECT   0x08 /* don't use object cache */
/* flags above 0x80 are sheepdog-internal */
#define SD_FLAG_CMD_PIGGYBACK   0x10

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* VDI exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* VDI is locked */
#define SD_RES_NO_VDI        0x08 /* No VDI found */
#define SD_RES_NO_SERV       0x09 /* No base Serv */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested VDI */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested VDI */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base VDI */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base VDI */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* VDI is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum VDIs */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Sheepdog is waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN 0x17 /* Sheepdog is waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */
#define SD_RES_HALT          0x19 /* Sheepdog is stopped doing IO */
#define SD_RES_READONLY      0x1A /* Object is read-only */
#define SD_RES_NETWORK_ERROR 0x1B
/* inode object in client is invalidated, refreshing is required */
#define SD_RES_INODE_INVALIDATED 0x1D

/* errors above 0x80 are sheepdog-internal */



#define STORE_LEN 16

#define SD_REQ_SIZE 72
#define SD_RSP_SIZE 72


struct sd_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t    id;
	uint64_t    data_length;
	union {
		struct {
            union {
    		    uint64_t	inode;
                uint64_t    objid;
            };
			uint64_t chunkid;
            union {
				uint64_t offset;
				uint64_t length;
			};
            uint32_t objindx;
            int group;
			uint16_t cs_id;
			uint16_t flags;
            uint8_t  etype;
            uint8_t  scid;
		} obj;

        struct {
            uint64_t inode;
            uint64_t chunkid;
            uint64_t offset1;
            uint64_t offset2;
            uint16_t cs_id;
        } rw_obj;

        struct {
            uint64_t objid;
            uint64_t chunkid;
	        uint16_t cs_id;
            uint8_t  etype;
            uint8_t  scid;
            uint32_t objindx;
            uint64_t obj_off;
            uint64_t offset;
            uint64_t length;
        }lc_obj;//for commit and load

		struct {
			uint64_t uid;
			uint64_t gid;
		}smb;

		struct {
			union {
				uint64_t mode;
				uint64_t item_count;
				uint64_t attrsize;
			};
			union {
				uint64_t fi;
				uint64_t inode;
			};
			union {
				uint64_t offset;
				uint64_t newparent;
				uint64_t attrinode;
			};
            uint64_t parent;
			union{
				int32_t flag;
				int32_t mask;
				int32_t rdev;
				int32_t to_set;
				int32_t datasync;
			};
            uint32_t snapid;
            uint16_t regionid;
		}smb_arg;
        struct {
            int mdsid;
            int group;
            int flag;
            int status;
            uint32_t mds_epoch;
            uint32_t cs_epoch;
            uint64_t inode;
        }mds;

        struct{
            uint64_t inode;
            uint64_t parent_id;
            uint64_t nodeid;
            uint32_t mdsid;
            uint32_t region;
            uint32_t pregion;
            uint32_t groupid;
        }mds_region;
		
		uint8_t		__pad[48];
	};
};

struct sd_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t    id;
	uint64_t    data_length;
	union {
		uint32_t        result;
		struct {
			uint32_t	__pad;
			uint8_t		status;
			uint8_t		reserved[3];
			uint64_t	offset;
		} obj;
		struct {
			uint32_t	__pad;
            uint32_t    snapid;
            uint16_t    regionid;
			uint8_t	    isdir;
			uint8_t		reserved[3];
			union {
				uint64_t sessionid;
				uint64_t fi;
				uint64_t inode;
			};
			uint64_t ret_inode;
		} smb;
		struct {
			uint32_t	__pad;
			uint8_t df;  
			uint8_t	reserved[3];
			uint64_t item_count;
			uint64_t offset;
		} smb_readdir;
        struct {
			uint32_t	__pad;
            uint32_t    mds_epoch;
            uint32_t    cs_epoch;
            uint64_t    nodeid;
		} mds;
		uint8_t		__pad[48];
	};
};

#endif
