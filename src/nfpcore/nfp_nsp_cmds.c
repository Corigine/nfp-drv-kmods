// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017 Netronome Systems, Inc. */

#include <linux/kernel.h>
#include <linux/slab.h>

#include "nfp.h"
#include "nfp_nsp.h"

struct nsp_identify {
	u8 version[40];
	u8 flags;
	u8 br_primary;
	u8 br_secondary;
	u8 br_nsp;
	__le16 primary;
	__le16 secondary;
	__le16 nsp;
	u8 reserved[6];
	__le64 sensor_mask;
};

struct nfp_nsp_identify *__nfp_nsp_identify(struct nfp_nsp *nsp)
{
	struct nfp_nsp_identify *nspi = NULL;
	struct nsp_identify *ni;
	int ret;

	if (nfp_nsp_get_abi_ver_minor(nsp) < 15)
		return NULL;

	ni = kzalloc(sizeof(*ni), GFP_KERNEL);
	if (!ni)
		return NULL;

	ret = nfp_nsp_read_identify(nsp, ni, sizeof(*ni));
	if (ret < 0) {
		nfp_err(nfp_nsp_cpp(nsp), "reading bsp version failed %d\n",
			ret);
		goto exit_free;
	}

	nspi = kzalloc(sizeof(*nspi), GFP_KERNEL);
	if (!nspi)
		goto exit_free;

	memcpy(nspi->version, ni->version, sizeof(nspi->version));
	nspi->version[sizeof(nspi->version) - 1] = '\0';
	nspi->flags = ni->flags;
	nspi->br_primary = ni->br_primary;
	nspi->br_secondary = ni->br_secondary;
	nspi->br_nsp = ni->br_nsp;
	nspi->primary = le16_to_cpu(ni->primary);
	nspi->secondary = le16_to_cpu(ni->secondary);
	nspi->nsp = le16_to_cpu(ni->nsp);
	nspi->abi_major = nfp_nsp_get_abi_ver_major(nsp);
	nspi->abi_minor = nfp_nsp_get_abi_ver_minor(nsp);
	nspi->sensor_mask = le64_to_cpu(ni->sensor_mask);

exit_free:
	kfree(ni);
	return nspi;
}

int nfp_hwmon_read_sensor(struct nfp_cpp *cpp, struct nfp_nsp_identify *nspi,
			  enum nfp_nsp_sensor_id id, long *val)
{
	unsigned long inv_cache = nspi->s_jifs + msecs_to_jiffies(nspi->s_upd_inr);
	struct nfp_sensors s;
	struct nfp_nsp *nsp;
	int ret;

	if (time_is_before_eq_jiffies(inv_cache)) {
		/* update all sensors from nsp */
		nsp = nfp_nsp_open(cpp);
		if (IS_ERR(nsp))
			return PTR_ERR(nsp);

		ret = nfp_nsp_read_sensors(nsp, nspi->sensor_mask, &s, sizeof(s));
		nfp_nsp_close(nsp);

		if (ret < 0)
			return ret;

		memcpy(&nspi->s_cached, &s, sizeof(s));
		nspi->s_jifs = jiffies;
	}

	switch (id) {
	case NFP_SENSOR_CHIP_TEMPERATURE:
		*val = le32_to_cpu(nspi->s_cached.chip_temp);
		break;
	case NFP_SENSOR_ASSEMBLY_POWER:
		*val = le32_to_cpu(nspi->s_cached.assembly_power);
		break;
	case NFP_SENSOR_ASSEMBLY_12V_POWER:
		*val = le32_to_cpu(nspi->s_cached.assembly_12v_power);
		break;
	case NFP_SENSOR_ASSEMBLY_3V3_POWER:
		*val = le32_to_cpu(nspi->s_cached.assembly_3v3_power);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
