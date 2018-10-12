// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017 Netronome Systems, Inc. */

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_nsp.h"
#include "nfp_main.h"

#define NFP_TEMP_MAX		(95 * 1000)
#define NFP_TEMP_CRIT		(105 * 1000)

#define NFP_POWER_MAX		(25 * 1000 * 1000)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static ssize_t
nfp_hwmon_show_input(struct device *dev, struct device_attribute *dev_attr,
		     char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(dev_attr);
	struct nfp_pf *pf = dev_get_drvdata(dev);
	long val;
	int ret;

	if (!(pf->nspi->sensor_mask & BIT(attr->index)))
		return -EINVAL;
	ret = nfp_hwmon_read_sensor(pf->cpp, attr->index, &val);
	if (ret < 0)
		return ret;

	return sprintf(buf, "%ld\n", val);
}

static ssize_t
nfp_hwmon_show_max(struct device *dev, struct device_attribute *dev_attr,
		   char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(dev_attr);

	switch (attr->index) {
	case NFP_SENSOR_CHIP_TEMPERATURE:
		return sprintf(buf, "%d\n", NFP_TEMP_MAX);
	case NFP_SENSOR_ASSEMBLY_POWER:
		return sprintf(buf, "%d\n", NFP_POWER_MAX);
	}
	return -EINVAL;
}

static ssize_t
nfp_hwmon_show_crit(struct device *dev, struct device_attribute *dev_attr,
		    char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(dev_attr);

	if (attr->index == NFP_SENSOR_CHIP_TEMPERATURE)
		return sprintf(buf, "%d\n", NFP_TEMP_CRIT);
	return -EINVAL;
}

static SENSOR_DEVICE_ATTR(temp1_input, 0444, nfp_hwmon_show_input, NULL,
			  NFP_SENSOR_CHIP_TEMPERATURE);
static SENSOR_DEVICE_ATTR(temp1_max, 0444, nfp_hwmon_show_max, NULL,
			  NFP_SENSOR_CHIP_TEMPERATURE);
static SENSOR_DEVICE_ATTR(temp1_crit, 0444, nfp_hwmon_show_crit, NULL,
			  NFP_SENSOR_CHIP_TEMPERATURE);
static SENSOR_DEVICE_ATTR(power1_input, 0444, nfp_hwmon_show_input, NULL,
			  NFP_SENSOR_ASSEMBLY_POWER);
static SENSOR_DEVICE_ATTR(power1_max, 0444, nfp_hwmon_show_max, NULL,
			  NFP_SENSOR_ASSEMBLY_POWER);
static SENSOR_DEVICE_ATTR(power2_input, 0444, nfp_hwmon_show_input, NULL,
			  NFP_SENSOR_ASSEMBLY_12V_POWER);
static SENSOR_DEVICE_ATTR(power3_input, 0444, nfp_hwmon_show_input, NULL,
			  NFP_SENSOR_ASSEMBLY_3V3_POWER);

static struct attribute *nfp_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp1_max.dev_attr.attr,
	&sensor_dev_attr_temp1_crit.dev_attr.attr,
	&sensor_dev_attr_power1_input.dev_attr.attr,
	&sensor_dev_attr_power1_max.dev_attr.attr,
	&sensor_dev_attr_power2_input.dev_attr.attr,
	&sensor_dev_attr_power3_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(nfp);

int nfp_hwmon_register(struct nfp_pf *pf)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	if (!IS_REACHABLE(CONFIG_HWMON))
#else
	if (!IS_ENABLED(CONFIG_HWMON))
#endif
		return 0;

	if (!pf->nspi) {
		nfp_warn(pf->cpp, "not registering HWMON (no NSP info)\n");
		return 0;
	}
	if (!pf->nspi->sensor_mask) {
		nfp_info(pf->cpp,
			 "not registering HWMON (NSP doesn't report sensors)\n");
		return 0;
	}

	pf->hwmon_dev = hwmon_device_register_with_groups(&pf->pdev->dev, "nfp",
							  pf, nfp_groups);
	return PTR_ERR_OR_ZERO(pf->hwmon_dev);
}

void nfp_hwmon_unregister(struct nfp_pf *pf)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	if (!IS_REACHABLE(CONFIG_HWMON))
#else
	if (!IS_ENABLED(CONFIG_HWMON))
#endif
		return;

	if (pf->hwmon_dev)
		hwmon_device_unregister(pf->hwmon_dev);
}
#else
int nfp_hwmon_register(struct nfp_pf *pf)
{
	return 0;
}

void nfp_hwmon_unregister(struct nfp_pf *pf)
{
}
#endif
