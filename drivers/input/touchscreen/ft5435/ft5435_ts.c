/*
 *
 * FocalTech ft5435 TouchScreen driver.
 *
 * Copyright (c) 2010  Focal tech Ltd.
 * Copyright (c) 2012-2014, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017 XiaoMi, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/firmware.h>
#include <linux/debugfs.h>
#include "ft5435_ts.h"


#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>

#elif defined(CONFIG_HAS_EARLYSUSPEND)
#include <linux/earlysuspend.h>
#include <linux/sensors.h>
/* Early-suspend level */
#define FT_SUSPEND_LEVEL 1
#endif

#if defined(FOCALTECH_AUTO_UPGRADE)
#define FTS_VENDOR_1	0x3b
#define FTS_VENDOR_2	0x51
#define FTS_VENDOR_3	0xD0

static unsigned char firmware_data_vendor1[] = {
	#include "HQ_D2_XiaoMi_FT5435_BIEL0X3b_Black_V0A_D01_20170712_app.i"
};

static unsigned char firmware_data_vendor2[] = {

	#include "HQ_D2_XiaoMi_FT5435_ofiml0X51_Black_V06_D01_20170804_app.i"
};

static unsigned char firmware_data_vendor3[] = {
	#include "HQ_D2_XiaoMi_FT5435_BIEL0X3b+CTC0Xd0_Black_V09_D01_20170811_app.i"

};
#endif
#define TCT_KEY_BACK  158
#define TCT_KEY_HOME 172
#define TCT_KEY_MENU 139



#define TCT_KEY_BACK_POS_X  100
#define TCT_KEY_BACK_POS_Y  1321

#define TCT_KEY_HOME_POS_X  360
#define TCT_KEY_HOME_POS_Y  1321

#define TCT_KEY_MENU_POS_X  620
#define TCT_KEY_MENU_POS_Y  1321

#define TX_NUM_MAX 50
#define RX_NUM_MAX 50



/* [PLATFORM]-Mod-BEGIN by TCTNB.ZXZ, PR-814306, 2014/10/24, add for rawdata test */
#define CONFIG_TCT_TP_FTDEBUG

/* [PLATFORM]-Mod-END by TCTNB.ZXZ */

#define FT_DRIVER_VERSION	0x02

#define TRULY 0x79
#define CHAOSHENG 0x57

#define FT_META_REGS		3
#define FT_ONE_TCH_LEN		6
#define FT_TCH_LEN(x)		(FT_META_REGS + FT_ONE_TCH_LEN * x)

#define FT_PRESS		0x7F
#define FT_MAX_ID		0x0F
#define FT_TOUCH_X_H_POS	3
#define FT_TOUCH_X_L_POS	4
#define FT_TOUCH_Y_H_POS	5
#define FT_TOUCH_Y_L_POS	6
#define FT_TD_STATUS		2
#define FT_TOUCH_EVENT_POS	3
#define FT_TOUCH_ID_POS		5
#define FT_TOUCH_DOWN		0
#define FT_TOUCH_CONTACT	2

/*register address*/
#define FT_REG_DEV_MODE		0x00
#define FT_DEV_MODE_REG_CAL	0x02
#define FT_REG_ID		0xA3
#define FT_REG_PMODE		0xA5
#define FT_REG_FW_VER		0xA6
#define FT_REG_FW_VENDOR_ID	0xA8
#define FT_REG_POINT_RATE	0x88
#define FT_REG_THGROUP		0x80
#define FT_REG_ECC		0xCC
#define FT_REG_RESET_FW		0x07
#define FT_REG_FW_MIN_VER	0xB2
#define FT_REG_FW_SUB_MIN_VER	0xB3

/* power register bits*/
#define FT_PMODE_ACTIVE		0x00
#define FT_PMODE_MONITOR	0x01
#define FT_PMODE_STANDBY	0x02
#define FT_PMODE_HIBERNATE	0x03
#define FT_FACTORYMODE_VALUE	0x40
#define FT_WORKMODE_VALUE	0x00
#define FT_RST_CMD_REG1		0xFC
#define FT_RST_CMD_REG2		0xBC
#define FT_READ_ID_REG		0x90
#define FT_ERASE_APP_REG	0x61
#define FT_ERASE_PANEL_REG	0x63
#define FT_FW_START_REG		0xBF

#define FT_STATUS_NUM_TP_MASK	0x0F

#define FT_VTG_MIN_UV		2600000
#define FT_VTG_MAX_UV		3300000
#define FT_I2C_VTG_MIN_UV	1800000
#define FT_I2C_VTG_MAX_UV	1800000

#define FT_COORDS_ARR_SIZE	4
#define MAX_BUTTONS		4

#define FT_8BIT_SHIFT		8
#define FT_4BIT_SHIFT		4
#define FT_FW_NAME_MAX_LEN	50

#define FT5316_ID		0x0A
#define FT5306I_ID		0x55
#define FT6X06_ID		0x06
#define FT6X36_ID		0x36
#define FT5X46_ID		0x54

#define FT_UPGRADE_AA		0xAA
#define FT_UPGRADE_55		0x55

#define FT_FW_MIN_SIZE		8
#define FT_FW_MAX_SIZE		65536

/* Firmware file is not supporting minor and sub minor so use 0 */
#define FT_FW_FILE_MAJ_VER(x)	((x)->data[(x)->size - 2])
#define FT_FW_FILE_MIN_VER(x)	0
#define FT_FW_FILE_SUB_MIN_VER(x) 0
#define FT_FW_FILE_VENDOR_ID(x)	((x)->data[(x)->size - 1])

#define FT_FW_FILE_MAJ_VER_FT6X36(x)	((x)->data[0x10a])
#define FT_FW_FILE_VENDOR_ID_FT6X36(x)	((x)->data[0x108])

/**
* Application data verification will be run before upgrade flow.
* Firmware image stores some flags with negative and positive value
* in corresponding addresses, we need pick them out do some check to
* make sure the application data is valid.
*/
#define FT_FW_CHECK(x, ts_data) \
	(ts_data->family_id == FT6X36_ID ? \
	(((x)->data[0x104] ^ (x)->data[0x105]) == 0xFF \
	&& ((x)->data[0x106] ^ (x)->data[0x107]) == 0xFF) : \
	(((x)->data[(x)->size - 8] ^ (x)->data[(x)->size - 6]) == 0xFF \
	&& ((x)->data[(x)->size - 7] ^ (x)->data[(x)->size - 5]) == 0xFF \
	&& ((x)->data[(x)->size - 3] ^ (x)->data[(x)->size - 4]) == 0xFF))

#define FT_MAX_TRIES		5
#define FT_RETRY_DLY		20

#define FT_MAX_WR_BUF		10
#define FT_MAX_RD_BUF		2
#define FT_FW_PKT_LEN		128
#define FT_FW_PKT_META_LEN	6
#define FT_FW_PKT_DLY_MS	20
#define FT_FW_LAST_PKT		0x6ffa
#define FT_EARSE_DLY_MS		100
#define FT_55_AA_DLY_NS		5000

#define FT_UPGRADE_LOOP		30
#define FT_CAL_START		0x04
#define FT_CAL_FIN		0x00
#define FT_CAL_STORE		0x05
#define FT_CAL_RETRY		100
#define FT_REG_CAL		0x00
#define FT_CAL_MASK		0x70

#define FT_INFO_MAX_LEN		512

#define FT_BLOADER_SIZE_OFF	12
#define FT_BLOADER_NEW_SIZE	30
#define FT_DATA_LEN_OFF_OLD_FW	8
#define FT_DATA_LEN_OFF_NEW_FW	14
#define FT_FINISHING_PKT_LEN_OLD_FW	6
#define FT_FINISHING_PKT_LEN_NEW_FW	12
#define FT_MAGIC_BLOADER_Z7	0x7bfa
#define FT_MAGIC_BLOADER_LZ4	0x6ffa
#define FT_MAGIC_BLOADER_GZF_30	0x7ff4
#define FT_MAGIC_BLOADER_GZF	0x7bf4

#define FTS_RESUME_WAIT_TIME    20

enum {
	FT_BLOADER_VERSION_LZ4 = 0,
	FT_BLOADER_VERSION_Z7 = 1,
	FT_BLOADER_VERSION_GZF = 2,
};

enum {
	FT_FT5336_FAMILY_ID_0x11 = 0x11,
	FT_FT5336_FAMILY_ID_0x12 = 0x12,
	FT_FT5336_FAMILY_ID_0x13 = 0x13,
	FT_FT5336_FAMILY_ID_0x14 = 0x14,
};

enum proximity_sensor_vendor {
	TAOS = 1,
	STK,
	TOTAL,
};

extern int set_usb_charge_mode_par;
extern int TX_NUM;
extern int RX_NUM;
extern int SCab_1;
extern int SCab_2;
extern int SCab_3;
extern int SCab_4;
extern int SCab_5;
extern int SCab_6;
extern int SCab_7;
extern int SCab_8;
extern int Save_rawData1[TX_NUM_MAX][RX_NUM_MAX];


#define FTS_FACTORYMODE_VALUE		0x40
#define FTS_WORKMODE_VALUE		0x00
static struct i2c_client  *ft_g_client;

#define FT_STORE_TS_INFO(buf, id, name, max_tch, group_id, fw_vkey_support, \
			fw_name, fw_maj, fw_min, fw_sub_min) \
			snprintf(buf, FT_INFO_MAX_LEN, \
				"controller\t= focaltech\n" \
				"model\t\t= 0x%x\n" \
				"name\t\t= %s\n" \
				"max_touches\t= %d\n" \
				"drv_ver\t\t= 0x%x\n" \
				"group_id\t= 0x%x\n" \
				"fw_vkey_support\t= %s\n" \
				"fw_name\t\t= %s\n" \
				"fw_ver\t\t= %d.%d.%d\n", id, name, \
				max_tch, FT_DRIVER_VERSION, group_id, \
				fw_vkey_support, fw_name, fw_maj, fw_min, \
				fw_sub_min)

#define FT_DEBUG_DIR_NAME	"ts_debug"

	u8 fts_fw_vendor_id;

struct ft5435_ts_data {
	struct i2c_client *client;
	struct input_dev *input_dev;
	const struct ft5435_ts_platform_data *pdata;
	struct regulator *vdd;
	struct regulator *vcc_i2c;
	char fw_name[FT_FW_NAME_MAX_LEN];
	bool loading_fw;
	u8 family_id;
	struct dentry *dir;
	u16 addr;
	bool suspended;
	char *ts_info;
	u8 *tch_data;
	u32 tch_data_len;
	u8 fw_ver[3];
	int touch_log_switch;
#if defined(FOCALTECH_FW_COMPAT)
	u8 fw_compat;
#endif
#if defined(FOCALTECH_PWRON_UPGRADE)
	struct delayed_work focaltech_update_work;
#endif
	u8 fw_vendor_id;
#if defined(CONFIG_FB)
	struct notifier_block fb_notif;
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	struct early_suspend early_suspend;
#endif

	struct pinctrl *ts_pinctrl;
	struct pinctrl_state *gpio_state_active;
	struct pinctrl_state *gpio_state_suspend;

	struct delayed_work resume_work;

#if defined(FOCALTECH_TP_GLOVE)
	u8 glove_id;
#endif

#if defined(USB_CHARGE_DETECT)
struct work_struct	work;
u8 charger_in;
#endif
#if defined(LEATHER_COVER)
struct work_struct work_cover;
u8 cover_on;
#endif
#if defined(VR_GLASS)
struct work_struct work_vr;
u8 vr_on;
#endif
};
static bool disable_keys_function = false;
bool is_ft5435 = false;
struct wakeup_source ft5436_wakelock;

static int ft5435_i2c_read(struct i2c_client *client, char *writebuf,
			   int writelen, char *readbuf, int readlen);
static int ft5x0x_read_reg(struct i2c_client *client, u8 addr, u8 *val);

#ifdef CONFIG_TOUCHPANEL_PROXIMITY_SENSOR
struct virtualpsensor {
	char const *name;
	struct input_dev *proximity_dev;
	int proximity_function;
	int vps_enabled;
	struct sensors_classdev vps_cdev;
	int value;
};

struct virtualpsensor *vps_ft5436;

#define VPS_NAME "virtual-proximity"

struct sensors_classdev virtual_sensors_proximity_cdev2 = {
		.name = VPS_NAME,
		.vendor = "NULL",
		.version = 1,
		.handle = SENSORS_PROXIMITY_HANDLE,
		.type = SENSOR_TYPE_PROXIMITY,
		.max_range = "5",
		.resolution = "5.0",
		.sensor_power = "3",
		.min_delay = 0, /* in microseconds */
		.fifo_reserved_event_count = 0,
		.fifo_max_event_count = 0,
		.enabled = 0,
		.delay_msec = 100,
		.sensors_enable = NULL,
		.sensors_poll_delay = NULL,
};

static int vps_set_enable(struct sensors_classdev *sensors_cdev, unsigned int enable);

static void tp_prox_sensor_enable(struct i2c_client *client, int enable);
#endif
static int ft5435_i2c_write(struct i2c_client *client, char *writebuf, int writelen);
static struct workqueue_struct *ft5435_wq_cover;
#if defined(VR_GLASS)
static struct workqueue_struct *ft5435_wq_vr;
#endif
static struct workqueue_struct *ft5435_wq;
static struct workqueue_struct *ft5435_resume_workqueue;
static struct ft5435_ts_data *g_ft5435_ts_data;

static int init_ok;
module_param_named(init_ok, init_ok, int, 0644);



static void ft5435_update_fw_ver(struct ft5435_ts_data *data)
{
	struct i2c_client *client = data->client;
	u8 reg_addr;
	int err;

	reg_addr = FT_REG_FW_VER;
	err = ft5435_i2c_read(client, &reg_addr, 1, &data->fw_ver[0], 1);
	if (err < 0)
		dev_err(&client->dev, "fw major version read failed");

	reg_addr = FT_REG_FW_MIN_VER;
	err = ft5435_i2c_read(client, &reg_addr, 1, &data->fw_ver[1], 1);
	if (err < 0)
		dev_err(&client->dev, "fw minor version read failed");

	reg_addr = FT_REG_FW_SUB_MIN_VER;
	err = ft5435_i2c_read(client, &reg_addr, 1, &data->fw_ver[2], 1);
	if (err < 0)
		dev_err(&client->dev, "fw sub minor version read failed");

	dev_info(&client->dev, "Firmware version = %d.%d.%d\n",
		data->fw_ver[0], data->fw_ver[1], data->fw_ver[2]);
}

static struct mutex g_device_mutex;

#if defined(FOCALTECH_TP_GESTURE)

/* [PLATFORM]-Mod-BEGIN by TCTNB.YQJ, FR797197, 2014/11/28 modify for 5x36 tp register of gesture  */
#define FT5435_REG_GESTURE_SET    0xd0
#define FT5435_REG_GESTURE_STATE    0xd3

#define  GESTURE_DB 0x24

/* [PLATFORM]-Mod-END by TCTNB.YQJ */
static int ft_tp_suspend(struct ft5435_ts_data *data);
#endif
static int ft5435_i2c_read(struct i2c_client *client, char *writebuf,
			   int writelen, char *readbuf, int readlen)
{
	int ret;
	if (writelen > 0) {
		struct i2c_msg msgs[] = {
			{
				 .addr = client->addr,
				 .flags = 0,
				 .len = writelen,
				 .buf = writebuf,
			 },
			{
				 .addr = client->addr,
				 .flags = I2C_M_RD,
				 .len = readlen,
				 .buf = readbuf,
			 },
		};
		ret = i2c_transfer(client->adapter, msgs, 2);
		if (ret < 0)
			dev_err(&client->dev, "%s: i2c read error.\n",
				__func__);
	} else {
		struct i2c_msg msgs[] = {
			{
				 .addr = client->addr,
				 .flags = I2C_M_RD,
				 .len = readlen,
				 .buf = readbuf,
			 },
		};
		ret = i2c_transfer(client->adapter, msgs, 1);
		if (ret < 0)
			dev_err(&client->dev, "%s:i2c read error.\n", __func__);
	}
	return ret;
}

static int ft5435_i2c_write(struct i2c_client *client, char *writebuf,
			    int writelen)
{
	int ret;

	struct i2c_msg msgs[] = {
		{
			 .addr = client->addr,
			 .flags = 0,
			 .len = writelen,
			 .buf = writebuf,
		 },
	};
	ret = i2c_transfer(client->adapter, msgs, 1);
	if (ret < 0)
		dev_err(&client->dev, "%s: i2c write error.\n", __func__);
	return ret;
}

#if defined(FOCALTECH_TP_GLOVE)

#define FOCALTECH_TP_GLOVE_SET    0xc0
#define FOCALTECH_TP_GLOVE_ENABLE 0x01

static struct device *tp_glove_dev;

/*
	u8 glove_id; 0: close glove function, 1: open glove function
*/
static ssize_t tp_glove_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ft5435_ts_data *data = NULL;

	data = dev_get_drvdata(dev);

	return sprintf(buf, "%d", data->glove_id);
}

static ssize_t tp_glove_id_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	struct ft5435_ts_data *data = NULL;
	unsigned long val = 0;
	char val_read = 0;
	ssize_t ret = -EINVAL;
	char txbuf[2];
	txbuf[0] = FOCALTECH_TP_GLOVE_SET;


	data = dev_get_drvdata(dev);

	if (data->suspended)
		return ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;


	if (0 == val) {
		data->glove_id = 0x00;
		txbuf[1] = 0x00;
		ft5435_i2c_write(data->client, txbuf, sizeof(txbuf));
	} else
	if (1 == val) {
		data->glove_id = 0x01;
		txbuf[1] = FOCALTECH_TP_GLOVE_ENABLE;
		ft5435_i2c_write(data->client, txbuf, sizeof(txbuf));
	} else {
		pr_err("invalid  command! \n");
		return -EPERM;
	}
	printk("set glove_id = %d \n", data->glove_id);
	ft5435_i2c_read(data->client, &txbuf[0], 1, &val_read, 1);
	printk("read glove_id = %d\n", val_read);

	return size;
}
static DEVICE_ATTR(glove_enable, 0644, tp_glove_id_show, tp_glove_id_store);

void tp_glove_register (struct ft5435_ts_data *data)
{
	int rc = 0;
	struct class *tp_device_class = NULL;
	tp_device_class = class_create(THIS_MODULE, "tp_glove");
	tp_glove_dev = device_create(tp_device_class, NULL, 0, NULL, "device");
	if (IS_ERR(tp_glove_dev))
		pr_err("Failed to create device(glove_ctrl)!\n");


	rc = device_create_file(tp_glove_dev, &dev_attr_glove_enable);
	if (rc < 0)
		pr_err("Failed to create device file(%s)!\n", dev_attr_glove_enable.attr.name);
	dev_set_drvdata(tp_glove_dev, data);

	printk("~~~~~ %s enable!!!!!\n", __func__);

}
#endif



static int ft5x0x_write_reg(struct i2c_client *client, u8 addr, const u8 val)
{
	u8 buf[2] = {0};

	buf[0] = addr;
	buf[1] = val;

	return ft5435_i2c_write(client, buf, sizeof(buf));
}

static int ft5x0x_read_reg(struct i2c_client *client, u8 addr, u8 *val)
{
	return ft5435_i2c_read(client, &addr, 1, val, 1);
}
#ifdef CONFIG_TOUCHPANEL_PROXIMITY_SENSOR
int virtual_psensor_input_register2(struct i2c_client *pClient)
{
	s32 nRetVal = 0;

	pr_err("*** %s() ***\n", __func__);

	vps_ft5436->proximity_dev = input_allocate_device();
	if (vps_ft5436->proximity_dev == NULL) {
		pr_err("*** input device allocation failed ***\n");
		return -ENOMEM;
	}

	vps_ft5436->proximity_dev->name = "proximity";
	vps_ft5436->proximity_dev->id.bustype = BUS_I2C;

	/* set the supported event type for input device */
	set_bit(EV_ABS, vps_ft5436->proximity_dev->evbit);
	set_bit(ABS_DISTANCE, vps_ft5436->proximity_dev->absbit);
	input_set_abs_params(vps_ft5436->proximity_dev, ABS_DISTANCE, 0, 1, 0, 0);

	nRetVal = input_register_device(vps_ft5436->proximity_dev);
	if (nRetVal < 0) {
		pr_err("*** Unable to register virtual P-sensor input device ***\n");
		return nRetVal;
	}

	vps_ft5436->vps_cdev = virtual_sensors_proximity_cdev2;
	vps_ft5436->vps_cdev.sensors_enable = vps_set_enable;
	vps_ft5436->vps_cdev.sensors_poll_delay = NULL;

	nRetVal = sensors_classdev_register(&pClient->dev, &vps_ft5436->vps_cdev);
	if (nRetVal) {
		pr_err("%s: Unable to register to sensors class: %d\n", __func__, nRetVal);
	return nRetVal;
	}

	return 0;
}
static void tp_prox_sensor_enable(struct i2c_client *client, int enable)
{
	u8 state;
	int ret = -1;

	if (client == NULL)
		return;

	if (gpio_is_valid(g_ft5435_ts_data->pdata->reset_gpio)) {
		gpio_set_value_cansleep(g_ft5435_ts_data->pdata->reset_gpio, 0);
		printk("reset tp ~~~ \n");
		msleep(g_ft5435_ts_data->pdata->hard_rst_dly);
		gpio_set_value_cansleep(g_ft5435_ts_data->pdata->reset_gpio, 1);
	}
	msleep(g_ft5435_ts_data->pdata->soft_rst_dly);

	if (enable) {
		state = 0x01;
	} else{
		state = 0x00;
	}
	ret = ft5x0x_write_reg(client, 0xB0, state);
	if (ret < 0)
		printk("[proxi_5206]write psensor switch command failed\n");
	ft5x0x_read_reg(client, 0xB0, &state);
	printk(" proximity function status[0x%x]\n", state);
	if ((!enable) && (g_ft5435_ts_data->suspended) && (g_ft5435_ts_data->gesture_id > 0)) {
		printk("double click function enable again \n");
		ft_tp_suspend(g_ft5435_ts_data);
	}

	return;
}
static int vps_set_enable(struct sensors_classdev *sensors_cdev, unsigned int enable)
{
	u8 status, reg_value;

	printk("FT vps_set_enable in. enable[%d]\n", enable);
	vps_ft5436->vps_enabled = enable ? 1 : 0;
	if (enable == 1) {
		ft5x0x_read_reg(g_ft5435_ts_data->client, 0xB0, &reg_value);
		printk("FT proxi_fts 0xB0 state value is0x%02X\n", reg_value);
		if (!(reg_value&0x01))
			tp_prox_sensor_enable(g_ft5435_ts_data->client, 1);
		ft5x0x_read_reg(g_ft5435_ts_data->client, 0x01, &status);
		printk("FT 0x01 reg status[0x%x]\n", status);
		if (status == 0xC0) {
			input_report_abs(vps_ft5436->proximity_dev, ABS_DISTANCE, 0);
			input_sync(vps_ft5436->proximity_dev);
		} else if (status == 0xE0) {
			input_report_abs(vps_ft5436->proximity_dev, ABS_DISTANCE, 1);
			input_sync(vps_ft5436->proximity_dev);
		}
	}

	return 0;
}

ssize_t ft_virtual_proximity_enable_show(struct device *pDevice, struct device_attribute *pAttr, char *pBuf)
{
	return sprintf(pBuf, "%d", vps_ft5436->vps_enabled);
}
ssize_t ft_virtual_proximity_enable_store(struct device *pDevice, struct device_attribute *pAttr, const char *pBuf, size_t nSize)
{
	int enable;
	if (pBuf != NULL) {
		sscanf(pBuf, "%d\n", &enable);
		vps_set_enable(&vps_ft5436->vps_cdev, enable);
		if (g_ft5435_ts_data->gesture_id == 0) {
			if (enable)
				device_init_wakeup(&g_ft5435_ts_data->client->dev, 1);
			else
				device_init_wakeup(&g_ft5435_ts_data->client->dev, 0);
		}
	}
	return nSize;
}

static DEVICE_ATTR(enable, 0664, ft_virtual_proximity_enable_show, ft_virtual_proximity_enable_store);

ssize_t ft_proximity_function_enable_show(struct device *pDevice, struct device_attribute *pAttr, char *pBuf)
{
	return sprintf(pBuf, "%x", vps_ft5436->proximity_function);
}

ssize_t ft_proximity_function_enable_store(struct device *pDevice, struct device_attribute *pAttr, const char *pBuf, size_t nSize)
{
	u32 nProximityMode;
	if (pBuf != NULL) {
		sscanf(pBuf, "%x", &nProximityMode);
		printk("nProximityMode = 0x%x\n", nProximityMode);
		vps_ft5436->proximity_function = nProximityMode;
		tp_prox_sensor_enable(g_ft5435_ts_data->client, nProximityMode);
	}
	return nSize;
}

static DEVICE_ATTR(proximity, 0664, ft_proximity_function_enable_show, ft_proximity_function_enable_store);

static int sys_device_create(void)
{
	struct class *virtual_proximity = NULL;
	struct device *virtual_proximity_device = NULL;

	virtual_proximity = class_create(THIS_MODULE, "virtual-proximity");
	if (IS_ERR(virtual_proximity))
		printk("Failed to create class(virtual_proximity)!\n");

	virtual_proximity_device = device_create(virtual_proximity, NULL, 0, NULL, "device");
	if (IS_ERR(virtual_proximity_device))
		printk("Failed to create device(virtual_proximity_device)!\n");

	if (device_create_file(virtual_proximity_device, &dev_attr_enable) < 0)
		printk("Failed to create device file(%s)!\n", dev_attr_enable.attr.name);

	if (device_create_file(virtual_proximity_device, &dev_attr_proximity) < 0)
		printk("Failed to create device file(%s)!\n", dev_attr_enable.attr.name);

	return 0;
}

#endif
#if defined(LEATHER_COVER)
void ft5435_enable_leather_cover(void)
{
	struct ft5435_ts_data *data;

	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;
	printk("[wxc]%s\n", __func__);
	data = g_ft5435_ts_data;

	data->cover_on = 1;

	queue_work(ft5435_wq_cover, &data->work_cover);
}
EXPORT_SYMBOL(ft5435_enable_leather_cover);
void ft5435_disable_leather_cover(void)
{
	struct ft5435_ts_data *data;


	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;
	printk("[wxc]%s\n", __func__);
	data = g_ft5435_ts_data;

	data->cover_on = 0;

	queue_work(ft5435_wq_cover, &data->work_cover);
}
EXPORT_SYMBOL(ft5435_disable_leather_cover);
void ft5435_change_leather_cover_switch(struct work_struct *work)
{
	u8 cover_flag = 0;
	struct ft5435_ts_data *data;


	data = g_ft5435_ts_data;

	if (data->suspended) {
		printk(KERN_ERR"data->suspended, data->cover_on = %d \n", data->cover_on);
		return ;
	}
	if (ft_g_client == NULL)
		return ;
	ft5x0x_read_reg(ft_g_client, 0xc1, &cover_flag);
	printk("[Fu]%s cover_flag=%d, data->cover_on=%d\n", __func__, cover_flag, data->cover_on);
	if (cover_flag != data->cover_on) {
		printk(KERN_ERR"[Fu]%s: Write %d to 0xc1\n", __FUNCTION__, data->cover_on);
		ft5x0x_write_reg(ft_g_client, 0xc1, data->cover_on);
	}
}

#endif
#if defined(VR_GLASS)
void ft5435_enable_vr(void)
{
	struct ft5435_ts_data *data;

	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;
	printk("[wxc]%s\n", __func__);
	data = g_ft5435_ts_data;

	data->vr_on = 1;

	queue_work(ft5435_wq_vr, &data->work_vr);
}
EXPORT_SYMBOL(ft5435_enable_vr);
void ft5435_disable_vr(void)
{
	struct ft5435_ts_data *data;

	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;
	printk("[wxc]%s\n", __func__);
	data = g_ft5435_ts_data;

	data->vr_on = 0;

	queue_work(ft5435_wq_vr, &data->work_vr);
}
EXPORT_SYMBOL(ft5435_disable_vr);
void ft5435_change_vr_switch(struct work_struct *work)
{
	u8 vr_flag = 0;
	struct ft5435_ts_data *data;


	data = g_ft5435_ts_data;

	if (data->suspended) {
		printk(KERN_ERR"data->suspended, data->vr_on = %d \n", data->vr_on);
		return ;
	}
	if (ft_g_client == NULL)
		return ;
	ft5x0x_read_reg(ft_g_client, 0xc1, &vr_flag);
	printk("[wxc]%s cover_flag=%d, data->vr_on=%d\n", __func__, vr_flag, data->vr_on);
	if (vr_flag != data->vr_on) {
		printk(KERN_ERR"[wxc]%s: Write %d to 0xc1\n", __FUNCTION__, data->vr_on);
		ft5x0x_write_reg(ft_g_client, 0xc1, data->vr_on);
	}
}

#endif
#if defined(USB_CHARGE_DETECT)
void ft5435_enable_change_scanning_frq(void)
{
	struct ft5435_ts_data *data;

	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;

	data = g_ft5435_ts_data;

	data->charger_in = 1;
	pr_debug("%s \n", __func__);

	queue_work(ft5435_wq, &data->work);
}
EXPORT_SYMBOL(ft5435_enable_change_scanning_frq);
void ft5435_disable_change_scanning_frq(void)
{
	struct ft5435_ts_data *data;


	if (!ft_g_client)
		return ;
	if (init_ok == 0)
		return;

	data = g_ft5435_ts_data;

	data->charger_in = 0;
	pr_debug("%s \n", __func__);

	queue_work(ft5435_wq, &data->work);
}
EXPORT_SYMBOL(ft5435_disable_change_scanning_frq);
void ft5435_change_scanning_frq_switch(struct work_struct *work)
{
	u8 charger_in_flag = 0;
	struct ft5435_ts_data *data;


	data = container_of(work, struct ft5435_ts_data, work);

	if (data->suspended) {
		printk(KERN_ERR"changer_in  = %d \n", data->charger_in);
		return ;
	}
	if (ft_g_client == NULL)
		return ;
	ft5x0x_read_reg(ft_g_client, 0x8b, &charger_in_flag);

	if (charger_in_flag != data->charger_in) {
		printk(KERN_ERR"[ft5435]%s: Write %d to 0x8b\n", __FUNCTION__, data->charger_in);
		ft5x0x_write_reg(ft_g_client, 0x8b, data->charger_in);
	}
}

void tpd_usb_plugin(bool mode)
{
	struct ft5435_ts_data *data = g_ft5435_ts_data;
	int ret = -1;
	if (data->suspended)
		return ;
	if (ft_g_client == NULL)
		return ;
	ret = ft5x0x_write_reg(ft_g_client, 0x8b, mode);
	if (ret < 0)
		pr_err("usb detect write err: %s %d.\n", __FUNCTION__, mode);
}

#else
void ft5435_enable_change_scanning_frq(void)
{
}
EXPORT_SYMBOL(ft5435_enable_change_scanning_frq);
void ft5435_disable_change_scanning_frq(void)
{
}
EXPORT_SYMBOL(ft5435_disable_change_scanning_frq);
#endif
static void ft5435_update_fw_vendor_id(struct ft5435_ts_data *data)
{
	struct i2c_client *client = data->client;
	u8 reg_addr;
	int err;

	reg_addr = FT_REG_FW_VENDOR_ID;
	err = ft5435_i2c_read(client, &reg_addr, 1, &data->fw_vendor_id, 1);
	if (err < 0)
		dev_err(&client->dev, "fw vendor id read failed");
	printk("[Fu]fw_vendor_id=0x%x\n", data->fw_vendor_id);
}


int fts_ctpm_auto_clb(struct i2c_client *client)
{
	unsigned char uc_temp = 0x00;
	unsigned char i = 0;

	/*start auto CLB */
	msleep(200);

	ft5x0x_write_reg(client, 0, FTS_FACTORYMODE_VALUE);
	/*make sure already enter factory mode */
	msleep(100);
	/*write command to start calibration */
	ft5x0x_write_reg(client, 2, 0x4);
	msleep(300);
	for (i = 0; i < 100; i++) {
		ft5x0x_read_reg(client, 0, &uc_temp);
		/*return to normal mode, calibration finish */
		if (0x0 == ((uc_temp & 0x70) >> 4))
			break;
	}

	msleep(200);
	/*calibration OK */
	msleep(300);
	ft5x0x_write_reg(client, 0, FTS_FACTORYMODE_VALUE);	/*goto factory mode for store */
	msleep(100);	/*make sure already enter factory mode */
	ft5x0x_write_reg(client, 2, 0x5);	/*store CLB result */
	msleep(300);
	ft5x0x_write_reg(client, 0, FTS_WORKMODE_VALUE);	/*return to normal mode */
	msleep(300);

	/*store CLB result OK */
	return 0;
}


/* [PLATFORM]-Mod-BEGIN by TCTNB.ZXZ, PR-814306, 2014/10/24, add for alto5 premium firmware version*/
#ifdef CONFIG_TCT_8X16_ALTO5_PREMIUM
static struct class *firm_ver_class;
static struct device *firm_ver_dev;

static ssize_t firm_ver_show (struct device *dev,
			struct device_attribute *attr, char *buf)
{
	u8 reg_ver;
	u8 reg_vendor;
	u8 ver_value, vendor_value;
	int err;
	reg_ver = FT_REG_FW_VER;
	err = ft5435_i2c_read(ft_g_client, &reg_ver, 1, &ver_value, 1);
	if (err < 0) {
		pr_err("TP FW version read failure\n");
		return sprintf (buf, "can't read firmware version \n");
	}
	pr_err("0xA6=0x%x\n", ver_value);
	reg_vendor = 0xA8;
	err = ft5435_i2c_read(ft_g_client, &reg_vendor, 1, &vendor_value, 1);
	if (err < 0) {
		pr_err("TP FW version read failure\n");
		return sprintf (buf, "ft irmware version(0xA6) is 0x%x\n can't read tp moudule  version \n" , ver_value);
	}
		pr_err("0xA8=0x%x\n", vendor_value);

	return sprintf (buf, "ft TP module  (0xA8)is 0x%x , fimware version(0xA6) is 0x%x\n", vendor_value, ver_value);
}

static DEVICE_ATTR(firm_ver, 0664, firm_ver_show, NULL);


static void firm_ver_attr_create(void)
{
	firm_ver_class = class_create(THIS_MODULE, "firmware_ver");
	if (IS_ERR(firm_ver_class))
		pr_err("Failed to create class(firm_ver_class)!\n");
	firm_ver_dev = device_create(firm_ver_class,
			NULL, 0, NULL, "device");
	if (IS_ERR(firm_ver_dev))
		pr_err("Failed to create device(gt_dclick_dev)!\n");


	if (device_create_file(firm_ver_dev, &dev_attr_firm_ver) < 0)
		pr_err("Failed to create device file(%s)!\n", dev_attr_firm_ver.attr.name);
}
#endif
/* [PLATFORM]-Mod-END by TCTNB.ZXZ*/

#if defined(FOCALTECH_TP_GESTURE)
#define WAKEUP_OFF 4
#define WAKEUP_ON 5
static bool gesture_func_on = true;
static int ft5435_gesture_switch(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	if (type == EV_SYN && code == SYN_CONFIG) {
		if (value == WAKEUP_OFF) {
			gesture_func_on = false;
		} else if (value == WAKEUP_ON) {
			gesture_func_on = true;
		}
	}
	return 0;
}

static int ft_tp_interrupt(struct ft5435_ts_data *data)
{
	int rc = 0;
	u8 reg_value, reg = 0x00;
	printk("[FTS]%s start\n", __func__);
	reg = FT5435_REG_GESTURE_STATE;
	rc = ft5435_i2c_read(data->client, &reg, 1, &reg_value, 1);
	if (rc < 0) {
		dev_err(&data->client->dev, "%s: read data fail\n", __func__);
		return rc;
	}

	if (GESTURE_DB == reg_value) {
		input_report_key(data->input_dev, KEY_WAKEUP, 1);
		input_sync(data->input_dev);
		input_report_key(data->input_dev, KEY_WAKEUP, 0);
		input_sync(data->input_dev);
		printk("[FTS]gesture KEY_POWER\n");
	} else {
		printk("[FTS]gesture_id, reg_value=0x%x \n", reg_value);
	}

	return rc;
}
#endif
static irqreturn_t ft5435_ts_interrupt(int irq, void *dev_id)
{
#if 1
	struct ft5435_ts_data *data = dev_id;
	struct input_dev *ip_dev;
	int rc, i, j;
	u32 id, x, y, status, num_touches;
	u8 reg = 0x00, *buf;
	bool update_input = false;

	#ifdef CONFIG_TOUCHPANEL_PROXIMITY_SENSOR
	u8 reg_value;
	u8 proximity_status;
	#endif
	#ifdef FOCALTECH_TP_GESTURE
	int ret = 0;
	u8 state = 0;
	#endif

	if (!data) {
		pr_err("%s: Invalid data\n", __func__);
		return IRQ_HANDLED;
	}
#if defined(FOCALTECH_TP_GESTURE)
	if (gesture_func_on) {
		ret = ft5x0x_read_reg(data->client, 0xd0, &state);
		if (ret < 0)
			printk("[FTS]read value fail\n");

		if (state == 1) {
			ft_tp_interrupt(data);
			return IRQ_HANDLED;
		}
	}
#endif

	ip_dev = data->input_dev;
	buf = data->tch_data;
#ifdef CONFIG_TOUCHPANEL_PROXIMITY_SENSOR
	if (vps_ft5436->vps_enabled) {
		ft5x0x_read_reg(data->client, 0xB0, &reg_value);
		printk("proxi_fts 0xB0 state value is0x%02X\n", reg_value);
		if (!(reg_value&0x01))
			tp_prox_sensor_enable(data->client, 1);
		ft5x0x_read_reg(data->client, 0x01, &proximity_status);
		printk("FT 0x01 reg proximity_status[0x%x]--%s\n", proximity_status, __FUNCTION__);
		if (proximity_status == 0xC0) {
			input_report_abs(vps_ft5436->proximity_dev, ABS_DISTANCE, 0);
			input_sync(vps_ft5436->proximity_dev);
			printk("[Fu]close\n");
		} else if (proximity_status == 0xE0) {
			_pm_wakeup_event(&ft5436_wakelock, 1000);
			input_report_abs(vps_ft5436->proximity_dev, ABS_DISTANCE, 1);
			input_sync(vps_ft5436->proximity_dev);
			printk("[Fu]leave\n");
		}
	}
#endif



	rc = ft5435_i2c_read(data->client, &reg, 1,
			buf, data->tch_data_len);
	if (rc < 0) {
		dev_err(&data->client->dev, "%s: read data fail\n", __func__);
		return IRQ_HANDLED;
	}

	for (i = 0; i < data->pdata->num_max_touches; i++) {
		id = (buf[FT_TOUCH_ID_POS + FT_ONE_TCH_LEN * i]) >> 4;
		if (id >= FT_MAX_ID)
			break;

		update_input = true;

		x = (buf[FT_TOUCH_X_H_POS + FT_ONE_TCH_LEN * i] & 0x0F) << 8 |
			(buf[FT_TOUCH_X_L_POS + FT_ONE_TCH_LEN * i]);
		y = (buf[FT_TOUCH_Y_H_POS + FT_ONE_TCH_LEN * i] & 0x0F) << 8 |
			(buf[FT_TOUCH_Y_L_POS + FT_ONE_TCH_LEN * i]);

		status = buf[FT_TOUCH_EVENT_POS + FT_ONE_TCH_LEN * i] >> 6;

		num_touches = buf[FT_TD_STATUS] & FT_STATUS_NUM_TP_MASK;

		/* invalid combination */
		if (!num_touches && !status && !id)
			break;
		input_mt_slot(ip_dev, id);

		if (x < data->pdata->panel_maxx && y < data->pdata->panel_maxy) {
			if (status == FT_TOUCH_DOWN || status == FT_TOUCH_CONTACT) {
				input_mt_report_slot_state(ip_dev, MT_TOOL_FINGER, 1);
				input_report_abs(ip_dev, ABS_MT_POSITION_X, x);
				input_report_abs(ip_dev, ABS_MT_POSITION_Y, y);
			} else {
				input_mt_report_slot_state(ip_dev, MT_TOOL_FINGER, 0);
			}
		} else{
			if (data->pdata->fw_vkey_support && !disable_keys_function) {
				for (j = 0; j < data->pdata->num_virkey; j++) {
					if (x == data->pdata->vkeys[j].x) {
						if (status == FT_TOUCH_DOWN || status == FT_TOUCH_CONTACT)
							input_report_key(data->input_dev, data->pdata->vkeys[j].keycode, true);
						else {
							input_report_key(data->input_dev, data->pdata->vkeys[j].keycode, false);
						}
					}
				}
			}
		}
	}

	if (update_input) {
#if defined(FOCALTECH_FAE_MOD)
		if (num_touches == 0) {	/* release all touches */
			for (i = 0; i < data->pdata->num_max_touches; i++) {
				input_mt_slot(data->input_dev, i);
				input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, 0);
			}
		}
#endif
		input_mt_report_pointer_emulation(ip_dev, false);
		input_sync(ip_dev);
	}
	#endif
	return IRQ_HANDLED;
}

static int ft5435_power_on(struct ft5435_ts_data *data, bool on)
{
	int rc;

	if (!on)
		goto power_off;

	rc = regulator_enable(data->vdd);
	if (rc) {
		dev_err(&data->client->dev,
			"Regulator vdd enable failed rc=%d\n", rc);
		return rc;
	}

#if 1
	rc = regulator_enable(data->vcc_i2c);
	if (rc) {
		dev_err(&data->client->dev,
			"Regulator vcc_i2c enable failed rc=%d\n", rc);
		regulator_disable(data->vdd);
	}
#endif


	return rc;

power_off:
#if 1
	rc = regulator_disable(data->vdd);
	if (rc) {
		dev_err(&data->client->dev,
			"Regulator vdd disable failed rc=%d\n", rc);
		return rc;
	}
#endif

#if 1
	rc = regulator_disable(data->vcc_i2c);
	if (rc) {
		dev_err(&data->client->dev,
			"Regulator vcc_i2c disable failed rc=%d\n", rc);
		rc = regulator_enable(data->vdd);
		if (rc) {
			dev_err(&data->client->dev,
				"Regulator vdd enable failed rc=%d\n", rc);
		}
	}
#endif


	return rc;
}

static int ft5435_power_init(struct ft5435_ts_data *data, bool on)
{
	int rc;

	if (!on)
		goto pwr_deinit;

	data->vdd = regulator_get(&data->client->dev, "vdd");
	if (IS_ERR(data->vdd)) {
		rc = PTR_ERR(data->vdd);
		dev_err(&data->client->dev,
			"Regulator get failed vdd rc=%d\n", rc);
		return rc;
	}

	if (regulator_count_voltages(data->vdd) > 0) {
		rc = regulator_set_voltage(data->vdd, FT_VTG_MIN_UV,
					   FT_VTG_MAX_UV);
		if (rc) {
			dev_err(&data->client->dev,
				"Regulator set_vtg failed vdd rc=%d\n", rc);
			goto reg_vdd_put;
		}
	}

#if 1
	data->vcc_i2c = regulator_get(&data->client->dev, "vcc_i2c");
	if (IS_ERR(data->vcc_i2c)) {
		rc = PTR_ERR(data->vcc_i2c);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_i2c rc=%d\n", rc);
		goto reg_vdd_set_vtg;
	}

	if (regulator_count_voltages(data->vcc_i2c) > 0) {
		rc = regulator_set_voltage(data->vcc_i2c, FT_I2C_VTG_MIN_UV,
					   FT_I2C_VTG_MAX_UV);
		if (rc) {
			dev_err(&data->client->dev,
			"Regulator set_vtg failed vcc_i2c rc=%d\n", rc);
			goto reg_vcc_i2c_put;
		}
	}
#endif


	return 0;

#if 1
reg_vcc_i2c_put:
	regulator_put(data->vcc_i2c);

reg_vdd_set_vtg:
	if (regulator_count_voltages(data->vdd) > 0)
		regulator_set_voltage(data->vdd, 0, FT_VTG_MAX_UV);
#endif

reg_vdd_put:
	regulator_put(data->vdd);
	return rc;

pwr_deinit:
	if (regulator_count_voltages(data->vdd) > 0)
		regulator_set_voltage(data->vdd, 0, FT_VTG_MAX_UV);

	regulator_put(data->vdd);

	return 0;
}

static int ft5435_ts_pinctrl_init(struct ft5435_ts_data *ft5435_data)
{
	int retval;

	/* Get pinctrl if target uses pinctrl */
	ft5435_data->ts_pinctrl = devm_pinctrl_get(&(ft5435_data->client->dev));
	if (IS_ERR_OR_NULL(ft5435_data->ts_pinctrl)) {
		dev_dbg(&ft5435_data->client->dev,
			"Target does not use pinctrl\n");
		retval = PTR_ERR(ft5435_data->ts_pinctrl);
		ft5435_data->ts_pinctrl = NULL;
		goto err_pinctrl_get;
	}

	ft5435_data->gpio_state_active
		= pinctrl_lookup_state(ft5435_data->ts_pinctrl,
			"pmx_ts_active");
	if (IS_ERR_OR_NULL(ft5435_data->gpio_state_active)) {
		dev_dbg(&ft5435_data->client->dev,
			"Can not get ts default pinstate\n");
		retval = PTR_ERR(ft5435_data->gpio_state_active);
		ft5435_data->ts_pinctrl = NULL;
		goto err_pinctrl_lookup;
	}

	ft5435_data->gpio_state_suspend
		= pinctrl_lookup_state(ft5435_data->ts_pinctrl,
			"pmx_ts_suspend");
	if (IS_ERR_OR_NULL(ft5435_data->gpio_state_suspend)) {
		dev_err(&ft5435_data->client->dev,
			"Can not get ts sleep pinstate\n");
		retval = PTR_ERR(ft5435_data->gpio_state_suspend);
		ft5435_data->ts_pinctrl = NULL;
		goto err_pinctrl_lookup;
	}

	return 0;
err_pinctrl_lookup:
	devm_pinctrl_put(ft5435_data->ts_pinctrl);
err_pinctrl_get:
	ft5435_data->ts_pinctrl = NULL;
	return retval;
}

static int ft5435_ts_pinctrl_select(struct ft5435_ts_data *ft5435_data,
						bool on)
{
	struct pinctrl_state *pins_state;
	int ret;
	pins_state = on ? ft5435_data->gpio_state_active
		: ft5435_data->gpio_state_suspend;
	if (!IS_ERR_OR_NULL(pins_state)) {
		ret = pinctrl_select_state(ft5435_data->ts_pinctrl, pins_state);
		if (ret) {
			dev_err(&ft5435_data->client->dev,
				"can not set %s pins\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");
			return ret;
		}
	} else {
		dev_err(&ft5435_data->client->dev,
			"not a valid '%s' pinstate\n",
				on ? "pmx_ts_active" : "pmx_ts_suspend");
	}
	return 0;
}

#if defined(FOCALTECH_TP_GESTURE)
static int  ft_tp_suspend(struct ft5435_ts_data *data)
{
	int i = 0;
	u8 state = 0;

	printk("[FTS] FTS_GESTRUE suspend\n");
	ft5x0x_write_reg(data->client, 0xd0, 0x01);
	ft5x0x_write_reg(data->client, 0xd1, 0xff);
	ft5x0x_write_reg(data->client, 0xd2, 0xff);
	ft5x0x_write_reg(data->client, 0xd5, 0xff);
	ft5x0x_write_reg(data->client, 0xd6, 0xff);
	ft5x0x_write_reg(data->client, 0xd7, 0xff);
	ft5x0x_write_reg(data->client, 0xd8, 0xff);
	msleep(10);

	for (i = 0; i < 10; i++) {
		printk("[FTS]tpd_suspend4 %d\t", i);
		ft5x0x_read_reg(data->client, 0xd0, &state);

		if (state == 1) {
			printk("[FTS]TPD gesture write 0x01 OK\n");
			break;
		} else {
			ft5x0x_write_reg(data->client, 0xd0, 0x01);
			ft5x0x_write_reg(data->client, 0xd1, 0xff);
			ft5x0x_write_reg(data->client, 0xd2, 0xff);
			ft5x0x_write_reg(data->client, 0xd5, 0xff);
			ft5x0x_write_reg(data->client, 0xd6, 0xff);
			ft5x0x_write_reg(data->client, 0xd7, 0xff);
			ft5x0x_write_reg(data->client, 0xd8, 0xff);
			msleep(10);
		}
	}

	if (i >= 9)
	{
		printk("[FTS]TPD gesture write 0x01 to d0 fail \n");
	}

	data->suspended = true;
	printk("[FTS] FTS_GESTRUE suspend end\n");
	return 0;
}
#endif

static void ft5435_resume_func(struct work_struct *work)
{
	struct ft5435_ts_data *data = g_ft5435_ts_data;
	printk("Enter %s", __func__);

	msleep(data->pdata->soft_rst_dly);

	ft5x0x_write_reg(data->client, 0x8c, 0x01);

#if defined(FOCALTECH_TP_GESTURE)
	if (gesture_func_on)
		disable_irq_wake(data->client->irq);
	else
		enable_irq(data->client->irq);
#else
	enable_irq(data->client->irq);
#endif

	data->suspended = false;
}

#ifdef CONFIG_PM
static int ft5435_ts_suspend(struct device *dev)
{
	struct ft5435_ts_data *data = g_ft5435_ts_data;
	char i;

	u8 state = -1;
	if (data->loading_fw) {
		dev_info(dev, "Firmware loading in process...\n");
		return 0;
	}

	if (data->suspended) {
		dev_info(dev, "Already in suspend state\n");
		return 0;
	}

	disable_irq(data->client->irq);

	/* release all touches */
	for (i = 0; i < data->pdata->num_max_touches; i++) {
		input_mt_slot(data->input_dev, i);
		input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, 0);
	}
	input_mt_report_pointer_emulation(data->input_dev, false);
	input_sync(data->input_dev);

#if defined(FOCALTECH_TP_GESTURE)
	{
		if (gesture_func_on) {
			enable_irq(data->client->irq);
			enable_irq_wake(data->client->irq);
			ft_tp_suspend(data);
			return 0;
		}
	}
#endif
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
		msleep(300);
	}
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		for (i = 0; i < 10; i++) {
			ft5x0x_write_reg(data->client, 0xa5, 0x03);
			ft5x0x_read_reg(data->client, 0xa5, &state);

			if ((state != 0) && (state != 1)) {
				printk("[FTS]Ft5435 TPDwrite  OK [%d]\n", i);
				break;
			} else {
				printk("[FTS]Ft5435 TPDwrite  Error[%d]\n", i);
			}
		}
	}

	data->suspended = true;
	return 0;
}

static int ft5435_ts_resume(struct device *dev)
{
	struct ft5435_ts_data *data = g_ft5435_ts_data;

	if (!data->suspended) {
		dev_dbg(dev, "Already in awake state\n");
		return 0;
	}

	/* release all touches */
	input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, 0);
	input_sync(data->input_dev);

	/*hw rst*/
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		gpio_set_value_cansleep(data->pdata->reset_gpio, 0);
		msleep(2);
		gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
	}

	cancel_delayed_work(&data->resume_work);
	queue_delayed_work(ft5435_resume_workqueue, &data->resume_work, msecs_to_jiffies(FTS_RESUME_WAIT_TIME));

#if defined(USB_CHARGE_DETECT)
	queue_work(ft5435_wq, &data->work);
#endif

#if defined(LEATHER_COVER)
	queue_work(ft5435_wq_cover, &data->work_cover);
#endif
#if defined(VR_GLASS)
	queue_work(ft5435_wq_vr, &data->work_vr);
#endif
	return 0;
}

static const struct dev_pm_ops ft5435_ts_pm_ops = {
#if (!defined(CONFIG_FB) && !defined(CONFIG_HAS_EARLYSUSPEND))
	.suspend = ft5435_ts_suspend,
	.resume = ft5435_ts_resume,
#endif
};

#else
static int ft5435_ts_suspend(struct device *dev)
{
	return 0;
}

static int ft5435_ts_resume(struct device *dev)
{
	return 0;
}

#endif

#if 1
#if defined(CONFIG_FB)
static int fb_notifier_callback(struct notifier_block *self,
				 unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct ft5435_ts_data *ft5435_data =
		container_of(self, struct ft5435_ts_data, fb_notif);

	if (evdata && evdata->data && event == FB_EVENT_BLANK &&
			ft5435_data && ft5435_data->client) {
		blank = evdata->data;
		if (*blank == FB_BLANK_UNBLANK)
			ft5435_ts_resume(&ft5435_data->client->dev);
		else if (*blank == FB_BLANK_POWERDOWN)
			ft5435_ts_suspend(&ft5435_data->client->dev);
	}
	return 0;
}
#elif defined(CONFIG_HAS_EARLYSUSPEND)
static void ft5435_ts_early_suspend(struct early_suspend *handler)
{
	struct ft5435_ts_data *data = container_of(handler,
						   struct ft5435_ts_data,
						   early_suspend);

	ft5435_ts_suspend(&data->client->dev);
}

static void ft5435_ts_late_resume(struct early_suspend *handler)
{
	struct ft5435_ts_data *data = container_of(handler,
						   struct ft5435_ts_data,
						   early_suspend);

	ft5435_ts_resume(&data->client->dev);
}
#endif
#else
#if defined(CONFIG_FB)
static void fb_notify_resume_work(struct work_struct *work)
{
	struct ft5435_ts_data *ft5435_data =
		container_of(work, struct ft5435_ts_data, fb_notify_work);
	ft5435_ts_resume(&ft5435_data->client->dev);
}

static int fb_notifier_callback(struct notifier_block *self,
				 unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct ft5435_ts_data *ft5435_data =
		container_of(self, struct ft5435_ts_data, fb_notif);

	if (evdata && evdata->data && ft5435_data && ft5435_data->client) {
		blank = evdata->data;
		if (ft5435_data->pdata->resume_in_workqueue) {
			if (event == FB_EARLY_EVENT_BLANK &&
						 *blank == FB_BLANK_UNBLANK)
				schedule_work(&ft5435_data->fb_notify_work);
			else if (event == FB_EVENT_BLANK &&
						 *blank == FB_BLANK_POWERDOWN) {
				flush_work(&ft5435_data->fb_notify_work);
				ft5435_ts_suspend(&ft5435_data->client->dev);
			}
		} else {
			if (event == FB_EVENT_BLANK) {
				if (*blank == FB_BLANK_UNBLANK)
					ft5435_ts_resume(
						&ft5435_data->client->dev);
				else if (*blank == FB_BLANK_POWERDOWN)
					ft5435_ts_suspend(
						&ft5435_data->client->dev);
			}
		}
	}

	return 0;
}
#elif defined(CONFIG_HAS_EARLYSUSPEND)
static void ftft5346_ts_early_suspend(struct early_suspend *handler)
{
	struct ftft5346_ts_data *data = container_of(handler,
						   struct ft5435_ts_data,
						   early_suspend);

	/*
	 * During early suspend/late resume, the driver doesn't access xPU/SMMU
	 * protected HW resources. So, there is no compelling need to block,
	 * but notifying the userspace that a power event has occurred is
	 * enough. Hence 'blocking' variable can be set to false.
	 */
	ft5435_secure_touch_stop(data, false);
	ft5435_ts_suspend(&data->client->dev);
}

static void ft5435_ts_late_resume(struct early_suspend *handler)
{
	struct ft5435_ts_data *data = container_of(handler,
						   struct ft5435_ts_data,
						   early_suspend);

	ft5435_secure_touch_stop(data, false);
	ft5435_ts_resume(&data->client->dev);
}
#endif

#endif

static int ft5435_auto_cal(struct i2c_client *client)
{
	struct ft5435_ts_data *data = i2c_get_clientdata(client);
	u8 temp = 0, i;

	/* set to factory mode */
	msleep(2 * data->pdata->soft_rst_dly);
	ft5x0x_write_reg(client, FT_REG_DEV_MODE, FT_FACTORYMODE_VALUE);
	msleep(data->pdata->soft_rst_dly);

	/* start calibration */
	ft5x0x_write_reg(client, FT_DEV_MODE_REG_CAL, FT_CAL_START);
	msleep(2 * data->pdata->soft_rst_dly);
	for (i = 0; i < FT_CAL_RETRY; i++) {
		ft5x0x_read_reg(client, FT_REG_CAL, &temp);
		/*return to normal mode, calibration finish */
		if (((temp & FT_CAL_MASK) >> FT_4BIT_SHIFT) == FT_CAL_FIN)
			break;
	}

	/*calibration OK */
	msleep(2 * data->pdata->soft_rst_dly);
	ft5x0x_write_reg(client, FT_REG_DEV_MODE, FT_FACTORYMODE_VALUE);
	msleep(data->pdata->soft_rst_dly);

	/* store calibration data */
	ft5x0x_write_reg(client, FT_DEV_MODE_REG_CAL, FT_CAL_STORE);
	msleep(2 * data->pdata->soft_rst_dly);

	/* set to normal mode */
	ft5x0x_write_reg(client, FT_REG_DEV_MODE, FT_WORKMODE_VALUE);
	msleep(2 * data->pdata->soft_rst_dly);

	return 0;
}

int hid_to_i2c(struct i2c_client *client)
{
	u8 auc_i2c_write_buf[5] = {0};
	int bRet = 0;

	auc_i2c_write_buf[0] = 0xeb;
	auc_i2c_write_buf[1] = 0xaa;
	auc_i2c_write_buf[2] = 0x09;

	ft5435_i2c_write(client, auc_i2c_write_buf, 3);

	msleep(10);

	auc_i2c_write_buf[0] = auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = 0;

	ft5435_i2c_read(client, auc_i2c_write_buf, 0, auc_i2c_write_buf, 3);


	if (1)
		bRet = 1;
	else bRet = 0;
		return bRet;
}


static int ft5435_fw_upgrade_start(struct i2c_client *client,
			const u8 *data, u32 data_len)
{
	struct ft5435_ts_data *ts_data = i2c_get_clientdata(client);
	struct fw_upgrade_info info = ts_data->pdata->info;
	u8 reset_reg;
	u8 w_buf[FT_MAX_WR_BUF] = {0}, r_buf[FT_MAX_RD_BUF] = {0};
	u8 pkt_buf[FT_FW_PKT_LEN + FT_FW_PKT_META_LEN];
	int i, j;
	u32 pkt_num, pkt_len, temp;

	u8 is_5336_fwsize_30 = false;
	u8 fw_ecc;
	hid_to_i2c(client);
	/* determine firmware size */
	if (*(data + data_len - FT_BLOADER_SIZE_OFF) == FT_BLOADER_NEW_SIZE)
		is_5336_fwsize_30 = true;
	else
		is_5336_fwsize_30 = false;

	for (i = 0, j = 0; i < FT_UPGRADE_LOOP; i++) {
		msleep(FT_EARSE_DLY_MS);
		/* reset - write 0xaa and 0x55 to reset register */
		if (ts_data->family_id == FT6X06_ID
			|| ts_data->family_id == FT6X36_ID)
			reset_reg = FT_RST_CMD_REG1;
		else
			reset_reg = FT_RST_CMD_REG1;

		ft5x0x_write_reg(client, reset_reg, FT_UPGRADE_AA);
		msleep(info.delay_aa);

		ft5x0x_write_reg(client, reset_reg, FT_UPGRADE_55);
		if (i <= (FT_UPGRADE_LOOP / 2))
			msleep(info.delay_55 + i * 3);
		else
			msleep(info.delay_55 - (i - (FT_UPGRADE_LOOP / 2)) * 2);
	hid_to_i2c(client);
	msleep(10);
	w_buf[0] = 0x55;
	w_buf[1] = 0xaa;
	temp = 0;
	do {
		temp++;
		ft5435_i2c_write(client, w_buf, 2);
		msleep(5);
	} while (temp < 1);

		/* check READ_ID */
		msleep(info.delay_readid);
		w_buf[0] = FT_READ_ID_REG;
		w_buf[1] = 0x00;
		w_buf[2] = 0x00;
		w_buf[3] = 0x00;

		ft5435_i2c_read(client, w_buf, 4, r_buf, 2);

		if (r_buf[0] != info.upgrade_id_1
			|| r_buf[1] != info.upgrade_id_2) {
			dev_err(&client->dev, "Upgrade ID mismatch(%d), IC=0x%x 0x%x, info=0x%x 0x%x\n",
				i, r_buf[0], r_buf[1],
				info.upgrade_id_1, info.upgrade_id_2);
		} else
			break;
	}

	if (i >= FT_UPGRADE_LOOP) {
		dev_err(&client->dev, "Abort upgrade\n");
		return -EIO;
	}
	/* erase app and panel paramenter area */
	w_buf[0] = FT_ERASE_APP_REG;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(info.delay_erase_flash);

	for (i = 0; i < 15; i++) {
		w_buf[0] = 0x6a;
		r_buf[0] = r_buf[1] = 0x00;
		ft5435_i2c_read(client, w_buf, 1, r_buf, 2);
		printk("1~~~~1 r_buf[0] =%x  r_buf[1] = %x  \n ", r_buf[0], r_buf[1]);
		if (0xF0 == r_buf[0] && 0xAA == r_buf[1])
			break;
		msleep(50);
	}

	w_buf[0] = 0xB0;
	w_buf[1] = (u8) ((data_len >> 16) & 0xFF);
	w_buf[2] = (u8) ((data_len >> 8) & 0xFF);
	w_buf[3] = (u8) (data_len & 0xFF);
	printk("data_len = %d \n", data_len);
	ft5435_i2c_write(client, w_buf, 4);


/*********Step 5:write firmware(FW) to ctpm flash*********/
	fw_ecc = 0;
	printk("Step 5:write firmware(FW) to ctpm flash\n");
	temp = 0;
	pkt_num = (data_len) / FT_FW_PKT_LEN;
	pkt_buf[0] = 0xbf;
	pkt_buf[1] = 0x00;
	printk("@@@@@pkt_num = %x \n", pkt_num);
	for (j = 0; j < pkt_num; j++) {
		temp = j * FT_FW_PKT_LEN;
		pkt_buf[2] = (u8) (temp >> 8);
		pkt_buf[3] = (u8) temp;
		pkt_len = FT_FW_PKT_LEN;
		pkt_buf[4] = (u8) (pkt_len >> 8);
		pkt_buf[5] = (u8) pkt_len;
		for (i = 0; i < FT_FW_PKT_LEN; i++) {
			pkt_buf[6 + i] = data[j * FT_FW_PKT_LEN + i];
			fw_ecc ^= pkt_buf[6 + i];
		}
		ft5435_i2c_write(client, pkt_buf, FT_FW_PKT_LEN + 6);

		for (i = 0; i < 30; i++) {
			w_buf[0] = 0x6a;
			r_buf[0] = r_buf[1] = 0x00;
			ft5435_i2c_read(client, w_buf, 1, r_buf, 2);

			if ((j + 0x1000) == (((r_buf[0]) << 8) | r_buf[1]))
				break;
			msleep(1);
		}
	}

	if ((data_len) % FT_FW_PKT_LEN > 0) {
		temp = pkt_num * FT_FW_PKT_LEN;
		pkt_buf[2] = (u8) (temp >> 8);
		pkt_buf[3] = (u8) temp;
		temp = (data_len) % FT_FW_PKT_LEN;
		pkt_buf[4] = (u8) (temp >> 8);
		pkt_buf[5] = (u8) temp;

		for (i = 0; i < temp; i++) {
			pkt_buf[6 + i] = data[pkt_num * FT_FW_PKT_LEN + i];
			fw_ecc ^= pkt_buf[6 + i];
		}
		ft5435_i2c_write(client, pkt_buf, temp + 6);

		for (i = 0; i < 30; i++) {
			w_buf[0] = 0x6a;
			r_buf[0] = r_buf[1] = 0x00;
			ft5435_i2c_read(client, w_buf, 1, r_buf, 2);
			printk("@~~~~@ r_buf[0] =%x  r_buf[1] = %x  j =%x \n ", r_buf[0], r_buf[1], j);
			if ((j + 0x1000) == (((r_buf[0]) << 8) | r_buf[1]))
				break;
			msleep(1);
		}
	}

	msleep(50);

	/*********Step 6: read out checksum***********************/
	/*send the opration head */
	printk("Step 6: read out checksum\n");
	w_buf[0] = 0x64;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(300);

	temp = 0;
	w_buf[0] = 0x65;
	w_buf[1] = (u8)(temp >> 16);
	w_buf[2] = (u8)(temp >> 8);
	w_buf[3] = (u8)(temp);
	temp = data_len;
	w_buf[4] = (u8)(temp >> 8);
	w_buf[5] = (u8)(temp);
	ft5435_i2c_write(client, w_buf, 6);
	msleep(data_len/256);

	for (i = 0; i < 100; i++) {
		w_buf[0] = 0x6a;
		r_buf[0] = r_buf[1] = 0x00;
		ft5435_i2c_read(client, w_buf, 1, r_buf, 2);
		printk("~~~~ r_buf[0] =%x  r_buf[1] = %x \n ", r_buf[0], r_buf[1]);
		if (0xF0 == r_buf[0] && 0x55 == r_buf[1])
			break;
		msleep(1);
	}
	w_buf[0] = 0x66;
	ft5435_i2c_read(client, w_buf, 1, r_buf, 1);
	if (r_buf[0] != fw_ecc)
	{
		dev_err(&client->dev, "[FTS]--ecc error! FW=%02x bt_ecc=%02x\n",
					r_buf[0],
					fw_ecc);

		return -EIO;
	}
	printk(KERN_WARNING "checksum %x %x \n", r_buf[0], fw_ecc);
	/* reset */
	w_buf[0] = FT_REG_RESET_FW;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(ts_data->pdata->soft_rst_dly);

	dev_info(&client->dev, "Firmware upgrade successful\n");

	return 0;
}
#if defined(FOCALTECH_AUTO_UPGRADE)

static int ft5x46_fw_upgrade_start(struct i2c_client *client,
			const u8 *data, u32 data_len)
{
	struct ft5435_ts_data *ts_data = i2c_get_clientdata(client);
	struct fw_upgrade_info info = ts_data->pdata->info;
	u8 w_buf[FT_MAX_WR_BUF] = {0}, r_buf[FT_MAX_RD_BUF] = {0};
	u8 pkt_buf[FT_FW_PKT_LEN + FT_FW_PKT_META_LEN];
	int i, j, temp;
	u32 pkt_num, pkt_len;
	u8 fw_ecc;
	int i_ret;

	printk("%s\n", __func__);
	i_ret = hid_to_i2c(client);

	if (i_ret == 0)
		printk("[FTS] hid1 change to i2c fail ! \n");

	for (i = 0, j = 0; i < FT_UPGRADE_LOOP; i++) {
		msleep(FT_EARSE_DLY_MS);

		/*********Step 1:Reset  CTPM *****/
		/*write 0xaa to register 0xfc */
		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_AA);
		msleep(2);

		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_55);

		msleep(200);

		i_ret = hid_to_i2c(client);

		if (i_ret == 0)
			printk("[FTS] hid%d change to i2c fail ! \n", i);

		msleep(10);

		/*********Step 2:Enter upgrade mode *****/
		w_buf[0] = FT_UPGRADE_55;
		w_buf[1] = FT_UPGRADE_AA;
		i_ret = ft5435_i2c_write(client, w_buf, 2);

		if (i_ret < 0) {
			printk("[FTS] failed writing  0x55 and 0xaa ! \n");
			continue;
		}

		/*********Step 3:check READ-ID***********************/
		msleep(1);
		w_buf[0] = FT_READ_ID_REG;
		w_buf[1] = 0x00;
		w_buf[2] = 0x00;
		w_buf[3] = 0x00;

		r_buf[0] = r_buf[1] = 0x00;

		ft5435_i2c_read(client, w_buf, 4, r_buf, 2);

		if (r_buf[0] == 0x54 && r_buf[1] == 0x2c) {
			printk("Upgrade ID mismatch(%d), IC=0x%x 0x%x, info=0x%x 0x%x\n",
				i, r_buf[0], r_buf[1], info.upgrade_id_1, info.upgrade_id_2);
			break;
		} else{
			printk("[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x\n",
				r_buf[0], r_buf[1]);
			continue;
		}
	}

	if (i >= FT_UPGRADE_LOOP) {
		dev_err(&client->dev, "Abort upgrade\n");
		return -EIO;
	}

	/******Step 4:erase app and panel paramenter area******/
	printk("Step 4:erase app and panel paramenter area\n");
	w_buf[0] = 0x61;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(1350);

	for (i = 0; i < 15; i++) {
		w_buf[0] = 0x6a;
		r_buf[0] = r_buf[1] = 0x00;
		ft5435_i2c_read(client, w_buf, 1, r_buf, 2);

		if (0xF0 == r_buf[0] && 0xAA == r_buf[1])
			break;
		msleep(50);

	}

	w_buf[0] = 0xB0;
	w_buf[1] = (u8) ((data_len >> 16) & 0xFF);
	w_buf[2] = (u8) ((data_len >> 8) & 0xFF);
	w_buf[3] = (u8) (data_len & 0xFF);

	ft5435_i2c_write(client, w_buf, 4);

	/*********Step 5:write firmware(FW) to ctpm flash*********/
	fw_ecc = 0;
	printk("Step 5:write firmware(FW) to ctpm flash\n");
	temp = 0;
	pkt_num = (data_len) / FT_FW_PKT_LEN;
	pkt_buf[0] = 0xbf;
	pkt_buf[1] = 0x00;

	for (j = 0; j < pkt_num; j++) {
		temp = j * FT_FW_PKT_LEN;
		pkt_buf[2] = (u8) (temp >> 8);
		pkt_buf[3] = (u8) temp;
		pkt_len = FT_FW_PKT_LEN;
		pkt_buf[4] = (u8) (pkt_len >> 8);
		pkt_buf[5] = (u8) pkt_len;

		for (i = 0; i < FT_FW_PKT_LEN; i++) {
			pkt_buf[6 + i] = data[j * FT_FW_PKT_LEN + i];
			fw_ecc ^= pkt_buf[6 + i];
		}
		ft5435_i2c_write(client, pkt_buf, FT_FW_PKT_LEN + 6);

		for (i = 0; i < 30; i++) {
			w_buf[0] = 0x6a;
			r_buf[0] = r_buf[1] = 0x00;
			ft5435_i2c_read(client, w_buf, 1, r_buf, 2);

			if ((j + 0x1000) == (((r_buf[0]) << 8) | r_buf[1]))
				break;
			msleep(1);

		}
	}

	if ((data_len) % FT_FW_PKT_LEN > 0) {
		temp = pkt_num * FT_FW_PKT_LEN;
		pkt_buf[2] = (u8) (temp >> 8);
		pkt_buf[3] = (u8) temp;
		temp = (data_len) % FT_FW_PKT_LEN;
		pkt_buf[4] = (u8) (temp >> 8);
		pkt_buf[5] = (u8) temp;

		for (i = 0; i < temp; i++) {
			pkt_buf[6 + i] = data[pkt_num* FT_FW_PKT_LEN + i];
			fw_ecc ^= pkt_buf[6 + i];
		}
		ft5435_i2c_write(client, pkt_buf, temp + 6);

		for (i = 0; i < 30; i++) {
			w_buf[0] = 0x6a;
			r_buf[0] = r_buf[1] = 0x00;
			ft5435_i2c_read(client, w_buf, 1, r_buf, 2);

			if ((j + 0x1000) == (((r_buf[0]) << 8) | r_buf[1]))
				break;
			msleep(1);

		}
	}

	msleep(50);

/*********Step 6: read out checksum***********************/
	/*send the opration head */
	printk("Step 6: read out checksum\n");
	w_buf[0] = 0x64;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(300);

	temp = 0;
	w_buf[0] = 0x65;
	w_buf[1] = (u8)(temp >> 16);
	w_buf[2] = (u8)(temp >> 8);
	w_buf[3] = (u8)(temp);
	temp = data_len;
	w_buf[4] = (u8)(temp >> 8);
	w_buf[5] = (u8)(temp);
	i_ret = ft5435_i2c_write(client, w_buf, 6);
	msleep(data_len/256);

	for (i = 0; i < 100; i++) {
		w_buf[0] = 0x6a;
		r_buf[0] = r_buf[1] = 0x00;
		ft5435_i2c_read(client, w_buf, 1, r_buf, 2);

		if (0xF0 == r_buf[0] && 0x55 == r_buf[1])
			break;
		msleep(1);

	}
	w_buf[0] = 0x66;
	ft5435_i2c_read(client, w_buf, 1, r_buf, 1);
	if (r_buf[0] != fw_ecc) {
		dev_err(&client->dev, "[FTS]--ecc error! FW=%02x bt_ecc=%02x\n",
					r_buf[0], fw_ecc);

		return -EIO;
	}
	printk(KERN_WARNING "checksum %X %X \n", r_buf[0], fw_ecc);

	/*********Step 7: reset the new FW***********************/
	printk("Step 7: reset the new FW\n");
	w_buf[0] = 0x07;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(130);

	return 0;
}
#endif
#if defined(FOCALTECH_FW_COMPAT)
static int ft5435_fw_upgrade_arbitrate(struct i2c_client *client)
{
	struct ft5435_ts_data *ts_data = i2c_get_clientdata(client);
	struct fw_upgrade_info info = ts_data->pdata->info;
	u8 reset_reg;
	u8 w_buf[FT_MAX_WR_BUF] = {0}, r_buf[FT_MAX_RD_BUF] = {0};
	int i;

	for (i = 0; i < FT_UPGRADE_LOOP; i++) {
		msleep(FT_EARSE_DLY_MS);
		/* reset - write 0xaa and 0x55 to reset register */
		if (ts_data->family_id == FT6X06_ID
			|| ts_data->family_id == FT6X36_ID)
			reset_reg = FT_RST_CMD_REG2;
		else
			reset_reg = FT_RST_CMD_REG1;

		ft5x0x_write_reg(client, reset_reg, FT_UPGRADE_AA);
		msleep(info.delay_aa);

		ft5x0x_write_reg(client, reset_reg, FT_UPGRADE_55);
		if (i <= (FT_UPGRADE_LOOP / 2))
			msleep(info.delay_55 + i * 3);
		else
			msleep(info.delay_55 - (i - (FT_UPGRADE_LOOP / 2)) * 2);

		/* Enter upgrade mode */
		w_buf[0] = FT_UPGRADE_55;
		ft5435_i2c_write(client, w_buf, 1);
		usleep(FT_55_AA_DLY_NS);
		w_buf[0] = FT_UPGRADE_AA;
		ft5435_i2c_write(client, w_buf, 1);

		/* check READ_ID */
		msleep(info.delay_readid);
		w_buf[0] = FT_READ_ID_REG;
		w_buf[1] = 0x00;
		w_buf[2] = 0x00;
		w_buf[3] = 0x00;

		ft5435_i2c_read(client, w_buf, 4, r_buf, 2);

		if (r_buf[0] != info.upgrade_id_1
			|| r_buf[1] != info.upgrade_id_2) {
			dev_err(&client->dev, "Upgrade ID mismatch(%d), IC=0x%x 0x%x, info=0x%x 0x%x\n",
				i, r_buf[0], r_buf[1],
				info.upgrade_id_1, info.upgrade_id_2);
		} else
			break;
	}

	if (i >= FT_UPGRADE_LOOP) {
		dev_err(&client->dev, "Abort upgrade\n");
		return -EIO;
	}

/* get tp vid */

	w_buf[0] = 0x03;
	w_buf[1] = 0x00;
	w_buf[2] = 0x78;
	w_buf[3] = 0x40;
	ft5435_i2c_read(client, w_buf, 4, r_buf, 1);
	ts_data->fw_compat = r_buf[0];
	printk("%s line=%d, fw_compat=%x \n", __func__, __LINE__, ts_data->fw_compat);

	/* reset */
	w_buf[0] = FT_REG_RESET_FW;
	ft5435_i2c_write(client, w_buf, 1);
	msleep(ts_data->pdata->soft_rst_dly);

/* New TP with fw_version >= 0x30 */
	if (ts_data->fw_compat >= 0x30) {
		strlcpy(ts_data->fw_name, "ft_fw3.bin", strlen("ft_fw3.bin") + 1);
	}

	return 0;
}
#endif

static unsigned int booting_into_recovery;
static int __init get_boot_mode(char *str)
{
	if (strcmp("boot_with_recovery", str) == 0)
		booting_into_recovery = 1;

	printk("zakk: booting_into_recovery=%d\n", booting_into_recovery);
	return 0;
}
__setup("androidboot.boot_reason=", get_boot_mode);

static int ft5435_fw_upgrade(struct device *dev, bool force)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	const struct firmware *fw = NULL;
	int rc;
	u8 fw_file_maj, fw_file_min, fw_file_sub_min, fw_file_vendor_id;
	bool fw_upgrade = false;

	if (data->suspended) {
		dev_err(dev, "Device is in suspend state: Exit FW upgrade\n");
		return -EBUSY;
	}

#if defined(FOCALTECH_FW_COMPAT)
	rc = ft5435_fw_upgrade_arbitrate(data->client);
	if (rc < 0) {
		printk(">>-- distinguish tp failed ! \n");
		return rc;
	}
#endif

	ft5435_update_fw_vendor_id(data);

	printk("[Fu]%s, booting_into_recovery=%d\n", __func__, booting_into_recovery);

	rc = request_firmware(&fw, data->fw_name, dev);


	if (rc < 0) {
		dev_err(dev, "[Fu]Request firmware failed - %s (%d)\n",
						data->fw_name, rc);
		return rc;
	}

	if (fw->size < FT_FW_MIN_SIZE || fw->size > FT_FW_MAX_SIZE) {
		dev_err(dev, "Invalid firmware size (%zu)\n", fw->size);
		rc = -EIO;
		goto rel_fw;
	}

	if (data->family_id == FT6X36_ID) {
		fw_file_maj = FT_FW_FILE_MAJ_VER_FT6X36(fw);
		fw_file_vendor_id = FT_FW_FILE_VENDOR_ID_FT6X36(fw);
	} else {
		fw_file_maj = FT_FW_FILE_MAJ_VER(fw);
		fw_file_vendor_id = FT_FW_FILE_VENDOR_ID(fw);
	}
	fw_file_min = FT_FW_FILE_MIN_VER(fw);
	fw_file_sub_min = FT_FW_FILE_SUB_MIN_VER(fw);

	printk("[Fu]Current firmware: %d.%d.%d", data->fw_ver[0],
				data->fw_ver[1], data->fw_ver[2]);
	printk("[Fu]New firmware: %d.%d.%d", fw_file_maj,
				fw_file_min, fw_file_sub_min);
	if (force)
		fw_upgrade = true;

	else if (fw_file_maj == 18 && data->fw_ver[0] != 18) {
		fw_upgrade = true;
		printk("\n[wxc]roll back firmware to v12 for temp\n");
	}

	else if ((data->fw_ver[0] < fw_file_maj) &&
		(data->pdata->ignore_id_check || (data->fw_vendor_id == fw_file_vendor_id)))
		fw_upgrade = true;

	if (!fw_upgrade) {
		dev_info(dev, "Exiting fw upgrade...\n");
		rc = -EFAULT;
		goto rel_fw;
	}

	/* start firmware upgrade */
	if (FT_FW_CHECK(fw, data)) {
		rc = ft5435_fw_upgrade_start(data->client, fw->data, fw->size);
		if (rc < 0)
			dev_err(dev, "update failed (%d). try later...\n", rc);
		else if (data->pdata->info.auto_cal)
			ft5435_auto_cal(data->client);
	} else {
		dev_err(dev, "FW format error\n");
		rc = -EIO;
	}

	ft5435_update_fw_ver(data);

	FT_STORE_TS_INFO(data->ts_info, data->family_id, data->pdata->name,
			data->pdata->num_max_touches, data->pdata->group_id,
			data->pdata->fw_vkey_support ? "yes" : "no",
			data->pdata->fw_name, data->fw_ver[0],
			data->fw_ver[1], data->fw_ver[2]);
rel_fw:
	release_firmware(fw);
	return rc;
}
#if defined(FOCALTECH_AUTO_UPGRADE)
static unsigned char ft5435_fw_Vid_get_from_boot(struct i2c_client *client)
{
	unsigned char auc_i2c_write_buf[10];
	u8 w_buf[FT_MAX_WR_BUF] = {0}, r_buf[FT_MAX_RD_BUF] = {0};
	unsigned char i = 0;
	unsigned char vid = 0xFF;
	int i_ret;

	i_ret = hid_to_i2c(client);

	for (i = 0; i < FT_UPGRADE_LOOP; i++) {
		msleep(FT_EARSE_DLY_MS);

		/*********Step 1:Reset  CTPM *****/
		/*write 0xaa to register 0xfc */
		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_AA);
		msleep(2);

		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_55);

		msleep(200);

		i_ret = hid_to_i2c(client);

		if (i_ret == 0)
			printk("[FTS] hid%d change to i2c fail ! \n", i);

		msleep(10);

		/*********Step 2:Enter upgrade mode *****/
		w_buf[0] = FT_UPGRADE_55;
		w_buf[1] = FT_UPGRADE_AA;

		i_ret = ft5435_i2c_write(client, w_buf, 2);

		if (i_ret < 0) {
			printk("[FTS] failed writing  0x55 and 0xaa ! \n");
			continue;
		}

		/*********Step 3:check READ-ID***********************/
		msleep(1);
		w_buf[0] = FT_READ_ID_REG;
		w_buf[1] = 0x00;
		w_buf[2] = 0x00;
		w_buf[3] = 0x00;

		r_buf[0] = r_buf[1] = 0x00;

		ft5435_i2c_read(client, w_buf, 4, r_buf, 2);

		if (r_buf[0] == 0x54 && r_buf[1] == 0x2c) {
			/*
			printk("Upgrade ID mismatch(%d), IC=0x%x 0x%x, info=0x%x 0x%x\n",
				i, r_buf[0], r_buf[1],info.upgrade_id_1, info.upgrade_id_2);
				*/
			break;
		} else{
			printk("[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x\n",
				r_buf[0], r_buf[1]);
			continue;
		}
	}

	if (i >= FT_UPGRADE_LOOP) {
		dev_err(&client->dev, "Abort upgrade\n");
		return -EIO;
	}

	printk("FTS_UPGRADE_LOOP ok is  i = %d \n", i);

	msleep(10);
	auc_i2c_write_buf[0] = 0x03;
	auc_i2c_write_buf[1] = 0x00;
	for (i = 0; i < FT_UPGRADE_LOOP; i++) {
		auc_i2c_write_buf[2] = 0xd7;
		auc_i2c_write_buf[3] = 0x83;
		i_ret = ft5435_i2c_write(client, auc_i2c_write_buf, 4);
		if (i_ret < 0) {
			printk("[FTS] Step 4: read lcm id from flash error when i2c write, i_ret = %d\n", i_ret);
			continue;
		}
		i_ret = ft5435_i2c_read(client, auc_i2c_write_buf, 0, r_buf, 2);
		if (i_ret < 0) {
			printk("[FTS] Step 4: read lcm id from flash error when i2c write, i_ret = %d\n", i_ret);
			continue;
		}

		vid = r_buf[1];

		printk("%s: REG VAL ID1 = 0x%x, ID2 = 0x%x\n", __func__, r_buf[0], r_buf[1]);
		break;
	}

	printk("%s: reset the tp\n", __func__);
	auc_i2c_write_buf[0] = 0x07;
	ft5435_i2c_write(client, auc_i2c_write_buf, 1);
	msleep(300);
	return vid;
}

static int ft5435_fw_upgrade_by_array_data(struct device *dev, char *fw_data, int size, bool force)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	struct firmware *fw = NULL;
	int rc;
	u8 fw_file_maj, fw_file_min, fw_file_sub_min, fw_file_vendor_id;
	bool fw_upgrade = false;
	char *pfw_data = fw_data;
	int fw_size = size;

	printk("%s, suspended=%d\n", __func__, data->suspended);
	if (data->suspended) {
		dev_err(dev, "Device is in suspend state: Exit FW upgrade\n");
		return -EBUSY;
	}

	fw = kzalloc(sizeof(struct firmware), GFP_KERNEL);
	fw->size = fw_size;
	fw->data = pfw_data;

	if (fw->size < FT_FW_MIN_SIZE || fw->size > FT_FW_MAX_SIZE) {
		dev_err(dev, "Invalid firmware size (%zu)\n", fw->size);
		rc = -EIO;
		goto rel_fw;
	}

	if (data->family_id == FT6X36_ID) {
		fw_file_maj = FT_FW_FILE_MAJ_VER_FT6X36(fw);
		fw_file_vendor_id = FT_FW_FILE_VENDOR_ID_FT6X36(fw);
	} else {
		fw_file_maj = FT_FW_FILE_MAJ_VER(fw);
		fw_file_vendor_id = FT_FW_FILE_VENDOR_ID(fw);
	}
	fw_file_min = FT_FW_FILE_MIN_VER(fw);
	fw_file_sub_min = FT_FW_FILE_SUB_MIN_VER(fw);

	dev_info(dev, "Current firmware: 0x%02x.%d.%d", data->fw_ver[0],
				data->fw_ver[1], data->fw_ver[2]);
	dev_info(dev, "New firmware: 0x%02x.%d.%d", fw_file_maj,
				fw_file_min, fw_file_sub_min);

	if (force)
		fw_upgrade = true;


	else if (data->fw_ver[0] != fw_file_maj)
		fw_upgrade = true;

	if (!fw_upgrade) {
		dev_info(dev, "Exiting fw upgrade...\n");
		rc = -EFAULT;
		goto rel_fw;
	}

	/* start firmware upgrade */
	if (data->family_id == FT5X46_ID) {
		rc = ft5x46_fw_upgrade_start(data->client, fw->data, fw->size);
		if (rc < 0)
			dev_err(dev, "update failed (%d). try later...\n", rc);
	} else if (FT_FW_CHECK(fw, data)) {
		rc = ft5435_fw_upgrade_start(data->client, fw->data, fw->size);
		if (rc < 0)
			dev_err(dev, "update failed (%d). try later...\n", rc);
		else if (data->pdata->info.auto_cal)
			ft5435_auto_cal(data->client);
	} else {
		dev_err(dev, "FW format error\n");
		rc = -EIO;
	}

	ft5435_update_fw_ver(data);

rel_fw:
	kfree(fw);
	printk("%s done\n", __func__);
	return rc;
}

#endif
#if defined(FOCALTECH_LOCK_DOWN_INFO)
#define CTP_PROC_LOCKDOWN_FILE "tp_lockdown_info"
static struct proc_dir_entry *ctp_lockdown_status_proc;
static char tp_lockdown_info[128];

static int ctp_lockdown_proc_show(struct seq_file *file, void *data)
{
	char temp[40] = {0};

	sprintf(temp, "%s\n", tp_lockdown_info);
	seq_printf(file, "%s\n", temp);

	return 0;
}

static int ctp_lockdown_proc_open (struct inode *inode, struct file *file)
{
	return single_open(file, ctp_lockdown_proc_show, inode->i_private);
}

static const struct file_operations ctp_lockdown_proc_fops = {
	.open = ctp_lockdown_proc_open,
	.read = seq_read,
};

static unsigned char ft5435_fw_LockDownInfo_get_from_boot(struct i2c_client *client, char *pProjectCode)
{
	unsigned char auc_i2c_write_buf[10];
	u8 w_buf[FT_MAX_WR_BUF] = {0}, r_buf[10] = {0};
	unsigned char i = 0, j = 0;


	int i_ret;

	printk("[fts]%s, fw_vendor_id=0x%02x\n", __func__, fts_fw_vendor_id);
	i_ret = hid_to_i2c(client);

	for (i = 0; i < FT_UPGRADE_LOOP; i++) {
		msleep(FT_EARSE_DLY_MS);

		/*********Step 1:Reset  CTPM *****/
		/*write 0xaa to register 0xfc */
		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_AA);
		msleep(2);

		ft5x0x_write_reg(client, 0xfc, FT_UPGRADE_55);

		msleep(200);

		i_ret = hid_to_i2c(client);

		if (i_ret == 0)
			printk("[FTS] hid%d change to i2c fail ! \n", i);

		msleep(10);

		/*********Step 2:Enter upgrade mode *****/
		w_buf[0] = FT_UPGRADE_55;
		w_buf[1] = FT_UPGRADE_AA;
		i_ret = ft5435_i2c_write(client, w_buf, 2);

		if (i_ret < 0) {
			printk("[FTS] failed writing  0x55 and 0xaa ! \n");
			continue;
		}

		/*********Step 3:check READ-ID***********************/
		msleep(10);
		w_buf[0] = FT_READ_ID_REG;
		w_buf[1] = 0x00;
		w_buf[2] = 0x00;
		w_buf[3] = 0x00;

		r_buf[0] = r_buf[1] = 0x00;

		ft5435_i2c_read(client, w_buf, 4, r_buf, 2);

		if (r_buf[0] == 0x54 && r_buf[1] == 0x2c) {
			/*
			printk("Upgrade ID mismatch(%d), IC=0x%x 0x%x, info=0x%x 0x%x\n",
				i, r_buf[0], r_buf[1],info.upgrade_id_1, info.upgrade_id_2);
				*/
			break;
		} else{
			printk("[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x\n",
				r_buf[0], r_buf[1]);
			continue;
		}
	}

	if (i >= FT_UPGRADE_LOOP) {
		dev_err(&client->dev, "Abort upgrade\n");
		return -EIO;
	}

	printk("%s, FTS_UPGRADE_LOOP ok is  i = %d \n", __func__, i);

	/********* Step 4: read project code from app param area ***********************/
	msleep(10);
	auc_i2c_write_buf[0] = 0x03;
	auc_i2c_write_buf[1] = 0x00;
	for (i = 0; i < FT_UPGRADE_LOOP; i++) {
		auc_i2c_write_buf[2] = 0xd7;
		auc_i2c_write_buf[3] = 0xa0;
		i_ret = ft5435_i2c_write(client, auc_i2c_write_buf, 4);
		if (i_ret < 0) {
			printk("[FTS] Step 4: read lcm id from flash error when i2c write, i_ret = %d\n", i_ret);
			continue;
		}
			msleep(10);
		i_ret = ft5435_i2c_read(client, auc_i2c_write_buf, 0, r_buf, 8);
		if (i_ret < 0) {
			printk("[FTS] Step 4: read lcm id from flash error when i2c write, i_ret = %d\n", i_ret);
			continue;
		}

		for (j = 0; j < 8; j++) {
			printk("%s: REG VAL = 0x%02x, j=%d\n", __func__, r_buf[j], j);
		}
		sprintf(pProjectCode, "%02x%02x%02x%02x%02x%02x%02x%02x", \
				r_buf[0], r_buf[1], r_buf[2], r_buf[3], r_buf[4], r_buf[5], r_buf[6], r_buf[7]);
		break;
	}

	printk("%s: reset the tp\n", __func__);
	auc_i2c_write_buf[0] = 0x07;
	ft5435_i2c_write(client, auc_i2c_write_buf, 1);
	msleep(300);
	return 0;
}
#endif


static ssize_t ft5435_update_fw_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	return snprintf(buf, 2, "%d\n", data->loading_fw);
}

static ssize_t ft5435_update_fw_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	unsigned long val;
	int rc;

	if (size > 2)
		return -EINVAL;

	rc = kstrtoul(buf, 10, &val);
	if (rc != 0)
		return rc;

	if (data->suspended) {
		dev_info(dev, "In suspend state, try again later...\n");
		return size;
	}

	mutex_lock(&data->input_dev->mutex);
	if (!data->loading_fw  && val) {
		data->loading_fw = true;
		ft5435_fw_upgrade(dev, false);
		data->loading_fw = false;
	}
	mutex_unlock(&data->input_dev->mutex);

	return size;
}

static DEVICE_ATTR(update_fw, 0664, ft5435_update_fw_show,
				ft5435_update_fw_store);

static ssize_t ft5435_force_update_fw_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	unsigned long val;
	int rc;

	if (size > 2)
		return -EINVAL;

	rc = kstrtoul(buf, 10, &val);
	if (rc != 0)
		return rc;

	mutex_lock(&data->input_dev->mutex);
	if (!data->loading_fw  && val) {
		data->loading_fw = true;
		ft5435_fw_upgrade(dev, true);
		data->loading_fw = false;
	}
	mutex_unlock(&data->input_dev->mutex);

	return size;
}

static DEVICE_ATTR(force_update_fw, 0664, ft5435_update_fw_show,
				ft5435_force_update_fw_store);

#ifdef SET_COVER_MODE
static int set_cover_mode_buf;
static ssize_t fts_set_cover_mode(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	int ret = 0;
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	sscanf(buf, "%d\n", &set_cover_mode_buf) ;
	switch (set_cover_mode_buf) {
	case 1:
		ret = ft5x0x_write_reg(data->client, 0xC1, 0x01);
		ft5x0x_write_reg(data->client, 0xC4, 0x00);
		ft5x0x_write_reg(data->client, 0xC5, 0xff);
		ft5x0x_write_reg(data->client, 0xC6, 0x00);
		ft5x0x_write_reg(data->client, 0xC7, 0xa0);
		break;
	case 2:
		ret = ft5x0x_write_reg(data->client, 0xC1, 0x01);
		ft5x0x_write_reg(data->client, 0xC4, 0x00);
		ft5x0x_write_reg(data->client, 0xC5, 0xff);
		ft5x0x_write_reg(data->client, 0xc6, 0x00);
		ft5x0x_write_reg(data->client, 0xC7, 0xff);
		break;
	case 0:
		ret = ft5x0x_write_reg(data->client, 0xC1, 0x00);
		break;
	}
	return ret;
}
static DEVICE_ATTR(set_cover_mode, 0220, NULL,
				fts_set_cover_mode);

#endif
static ssize_t ft5435_fw_name_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	return snprintf(buf, FT_FW_NAME_MAX_LEN - 1, "%s\n", data->fw_name);
}

static ssize_t ft5435_fw_name_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);

	if (size > FT_FW_NAME_MAX_LEN - 1)
		return -EINVAL;

	strlcpy(data->fw_name, buf, size);
	if (data->fw_name[size-1] == '\n')
		data->fw_name[size-1] = 0;

	return size;
}

static DEVICE_ATTR(fw_name, 0664, ft5435_fw_name_show, ft5435_fw_name_store);

static ssize_t ft5435_fw_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ft5435_ts_data *data = dev_get_drvdata(dev);
	return sprintf(buf, "v%d.%d.%d\n", data->fw_ver[0], data->fw_ver[1], data->fw_ver[2]);
}

static ssize_t ft5435_fw_version_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	return 0;
}

static DEVICE_ATTR(fw_version, 0664, ft5435_fw_version_show, ft5435_fw_version_store);


static bool ft5435_debug_addr_is_valid(int addr)
{
	if (addr < 0 || addr > 0xFF) {
		pr_err("FT reg address is invalid: 0x%x\n", addr);
		return false;
	}

	return true;
}

static int ft5435_debug_data_set(void *_data, u64 val)
{
	struct ft5435_ts_data *data = _data;

	mutex_lock(&data->input_dev->mutex);

	if (ft5435_debug_addr_is_valid(data->addr))
		dev_info(&data->client->dev,
			"Writing into FT registers not supported\n");

	mutex_unlock(&data->input_dev->mutex);

	return 0;
}

static int ft5435_debug_data_get(void *_data, u64 *val)
{
	struct ft5435_ts_data *data = _data;
	int rc;
	u8 reg;

	mutex_lock(&data->input_dev->mutex);

	if (ft5435_debug_addr_is_valid(data->addr)) {
		rc = ft5x0x_read_reg(data->client, data->addr, &reg);
		if (rc < 0)
			dev_err(&data->client->dev,
				"FT read register 0x%x failed (%d)\n",
				data->addr, rc);
		else
			*val = reg;
	}

	mutex_unlock(&data->input_dev->mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_data_fops, ft5435_debug_data_get,
			ft5435_debug_data_set, "0x%02llX\n");

static int ft5435_debug_addr_set(void *_data, u64 val)
{
	struct ft5435_ts_data *data = _data;

	if (ft5435_debug_addr_is_valid(val)) {
		mutex_lock(&data->input_dev->mutex);
		data->addr = val;
		mutex_unlock(&data->input_dev->mutex);
	}

	return 0;
}

static int ft5435_debug_addr_get(void *_data, u64 *val)
{
	struct ft5435_ts_data *data = _data;

	mutex_lock(&data->input_dev->mutex);

	if (ft5435_debug_addr_is_valid(data->addr))
		*val = data->addr;

	mutex_unlock(&data->input_dev->mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_addr_fops, ft5435_debug_addr_get,
			ft5435_debug_addr_set, "0x%02llX\n");

static int ft5435_debug_suspend_set(void *_data, u64 val)
{
	struct ft5435_ts_data *data = _data;

	mutex_lock(&data->input_dev->mutex);

	if (val)
		ft5435_ts_suspend(&data->client->dev);
	else
		ft5435_ts_resume(&data->client->dev);

	mutex_unlock(&data->input_dev->mutex);

	return 0;
}

static int ft5435_debug_suspend_get(void *_data, u64 *val)
{
	struct ft5435_ts_data *data = _data;

	mutex_lock(&data->input_dev->mutex);
	*val = data->suspended;
	mutex_unlock(&data->input_dev->mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_suspend_fops, ft5435_debug_suspend_get,
			ft5435_debug_suspend_set, "%lld\n");

static int ft5435_debug_dump_info(struct seq_file *m, void *v)
{
	struct ft5435_ts_data *data = m->private;

	seq_printf(m, "%s\n", data->ts_info);

	return 0;
}

static int debugfs_dump_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, ft5435_debug_dump_info, inode->i_private);
}

static const struct file_operations debug_dump_info_fops = {
	.owner		= THIS_MODULE,
	.open		= debugfs_dump_info_open,
	.read		= seq_read,
	.release	= single_release,
};

#ifdef CONFIG_OF
static int ft5435_get_dt_coords(struct device *dev, char *name,
				struct ft5435_ts_platform_data *pdata)
{
	u32 coords[FT_COORDS_ARR_SIZE];
	struct property *prop;
	struct device_node *np = dev->of_node;
	int coords_size, rc;

	prop = of_find_property(np, name, NULL);
	if (!prop)
		return -EINVAL;
	if (!prop->value)
		return -ENODATA;

	coords_size = prop->length / sizeof(u32);
	if (coords_size != FT_COORDS_ARR_SIZE) {
		dev_err(dev, "invalid %s\n", name);
		return -EINVAL;
	}

	rc = of_property_read_u32_array(np, name, coords, coords_size);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read %s\n", name);
		return rc;
	}

	if (!strcmp(name, "focaltech,panel-coords")) {
		pdata->panel_minx = coords[0];
		pdata->panel_miny = coords[1];
		pdata->panel_maxx = coords[2];
		pdata->panel_maxy = coords[3];
	} else if (!strcmp(name, "focaltech,display-coords")) {
		pdata->x_min = coords[0];
		pdata->y_min = coords[1];
		pdata->x_max = coords[2];
		pdata->y_max = coords[3];
	} else {
		dev_err(dev, "unsupported property %s\n", name);
		return -EINVAL;
	}

	return 0;
}
static int ft5435_get_dt_vkey(struct device *dev, struct ft5435_ts_platform_data *pdata)
{
	u32 coords[FOCALTECH_MAX_VKEY_NUM];
	struct property *prop;
	struct device_node *np = dev->of_node;
	int coords_size, rc, i;
	char name[128];
	memset(name, 0, sizeof(name));

	sprintf(name, "focal,virtual_key_1");
	prop = of_find_property(np, name, NULL);
	printk("[%s]000\n", __FUNCTION__);
	if (!prop)
		return -EINVAL;
	printk("[%s]111\n", __FUNCTION__);
	if (!prop->value)
		return -ENODATA;
	printk("[%s]222\n", __FUNCTION__);
	coords_size = prop->length / sizeof(u32);
	if (coords_size != pdata->num_virkey) {
		printk("[%s]invalid %s\n", __FUNCTION__, name);
		return -EINVAL;
	}
	printk("[%s]333\n", __FUNCTION__);
	for (i = 0; i < pdata->num_virkey; i++) {
		sprintf(name, "focal,virtual_key_%d", i+1);
		rc = of_property_read_u32_array(np, name, coords, coords_size);
		if (rc && (rc != -EINVAL)) {
			printk("[%s]Unable to read %s\n", __FUNCTION__, name);
			return rc;
		}

		pdata->vkeys[i].keycode = coords[0];
		pdata->vkeys[i].x = coords[1];
		pdata->vkeys[i].y = coords[2];
		printk("[FTS]keycode = %d, x= %d, y=%d \n", pdata->vkeys[i].keycode,
			pdata->vkeys[i].x, pdata->vkeys[i].y);
	}
	printk("[%s]5555\n", __FUNCTION__);
	return 0;


}

static int ft5435_parse_dt(struct device *dev,
			struct ft5435_ts_platform_data *pdata)
{
	int rc;
	struct device_node *np = dev->of_node;
	u32 temp_val;

	pdata->name = "focaltech";
	rc = of_property_read_string(np, "focaltech,name", &pdata->name);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read name\n");
		return rc;
	}

	rc = ft5435_get_dt_coords(dev, "focaltech,panel-coords", pdata);
	if (rc && (rc != -EINVAL))
		return rc;

	rc = ft5435_get_dt_coords(dev, "focaltech,display-coords", pdata);
	if (rc)
		return rc;

	pdata->i2c_pull_up = of_property_read_bool(np,
						"focaltech,i2c-pull-up");

	pdata->no_force_update = of_property_read_bool(np,
						"focaltech,no-force-update");
	/* reset, irq gpio info */
	pdata->reset_gpio = of_get_named_gpio_flags(np, "focaltech,reset-gpio",
				0, &pdata->reset_gpio_flags);
	if (pdata->reset_gpio < 0)
		return pdata->reset_gpio;

	pdata->irq_gpio = of_get_named_gpio_flags(np, "focaltech,irq-gpio",
				0, &pdata->irq_gpio_flags);
	if (pdata->irq_gpio < 0)
		return pdata->irq_gpio;

	pdata->fw_name = "ft_fw.bin";
	rc = of_property_read_string(np, "focaltech,fw-name", &pdata->fw_name);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw name\n");
		return rc;
	}

	rc = of_property_read_u32(np, "focaltech,group-id", &temp_val);
	if (!rc)
		pdata->group_id = temp_val;
	else
		return rc;

	rc = of_property_read_u32(np, "focaltech,hard-reset-delay-ms",
							&temp_val);
	if (!rc)
		pdata->hard_rst_dly = temp_val;
	else
		return rc;

	rc = of_property_read_u32(np, "focaltech,soft-reset-delay-ms",
							&temp_val);
	if (!rc)
		pdata->soft_rst_dly = temp_val;
	else
		return rc;

	rc = of_property_read_u32(np, "focaltech,num-max-touches", &temp_val);
	if (!rc)
		pdata->num_max_touches = temp_val;
	else
		return rc;

	rc = of_property_read_u32(np, "focaltech,fw-delay-aa-ms", &temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw delay aa\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.delay_aa =  temp_val;

	rc = of_property_read_u32(np, "focaltech,fw-delay-55-ms", &temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw delay 55\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.delay_55 =  temp_val;

	rc = of_property_read_u32(np, "focaltech,fw-upgrade-id1", &temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw upgrade id1\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.upgrade_id_1 =  temp_val;

	rc = of_property_read_u32(np, "focaltech,fw-upgrade-id2", &temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw upgrade id2\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.upgrade_id_2 =  temp_val;

	rc = of_property_read_u32(np, "focaltech,fw-delay-readid-ms",
							&temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw delay read id\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.delay_readid =  temp_val;

	rc = of_property_read_u32(np, "focaltech,fw-delay-era-flsh-ms",
							&temp_val);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "Unable to read fw delay erase flash\n");
		return rc;
	} else if (rc != -EINVAL)
		pdata->info.delay_erase_flash =  temp_val;

	pdata->info.auto_cal = of_property_read_bool(np,
					"focaltech,fw-auto-cal");

	pdata->resume_in_workqueue = of_property_read_bool(np,
						"focaltech,resume-in-workqueue");


	pdata->fw_vkey_support = of_property_read_bool(np,
						"focaltech,fw-vkey-support");

	pdata->ignore_id_check = of_property_read_bool(np,
						"focaltech,ignore-id-check");

	rc = of_property_read_u32(np, "focaltech,num-virtual-key", &temp_val);
	if (rc && (rc != -EINVAL)) {
		printk("[%s]focaltech,num-virtual-key,dts parase failed\n", __FUNCTION__);
		return rc;
	} else if (rc != -EINVAL) {
		pdata->num_virkey = temp_val;
	}
	rc = ft5435_get_dt_vkey(dev, pdata);
	if (rc) {
		printk("[%s]focaltech,ft5435_get_dt_vkey failed\n", __FUNCTION__);
		return rc;
	}

	rc = of_property_read_u32(np, "focaltech,family-id", &temp_val);
	if (!rc)
		pdata->family_id = temp_val;
	else
		return rc;

	return 0;
}
#else
static int ft5435_parse_dt(struct device *dev,
			struct ft5435_ts_platform_data *pdata)
{
	return -ENODEV;
}
#endif

#if defined(FOCALTECH_PWRON_UPGRADE)
static void ft_init_update_work(struct work_struct *work)
{
	struct delayed_work *delay_work;
	struct ft5435_ts_data *ts;
	struct device *dev;

	delay_work = to_delayed_work(work);
	ts = container_of(delay_work, struct ft5435_ts_data, focaltech_update_work);
	dev = &ts->input_dev->dev;

	mutex_lock(&ts->input_dev->mutex);
	ft5435_fw_upgrade(dev, false);

	mutex_unlock(&ts->input_dev->mutex);
}

u8 ft_init_update_proc(struct ft5435_ts_data *ts)
{
	dev_dbg(&ts->client->dev, "Ready to run update work.");

	INIT_DELAYED_WORK(&ts->focaltech_update_work, ft_init_update_work);
	schedule_delayed_work(&ts->focaltech_update_work,
		msecs_to_jiffies(3000));

	return 0;
}
#endif

#if defined(FOCALTECH_TP_GESTURE)
void keyset_for_tp_gesture(struct input_dev *input_dev)
{
	input_set_capability(input_dev, EV_KEY, KEY_WAKEUP);

}
#endif


#if defined(RAWDATA_INTERFACE)
extern struct ft5435_rawdata_test_result ft5436_rawdata_test_result;
extern int rawdata_fail_num;
#define FTS_TX_MAX	40
#define FTS_RX_MAX	40
#define FTS_DEVICE_MODE_REG	0x00
#define FTS_RAW_READ_REG		0x01
#define FTS_RAW_BEGIN_REG		0x10

static int ft5x0x_enter_factory(void)
{
	u8 regval;

	ft5x0x_write_reg(ft_g_client, 0, 0x40);
	mdelay(100);
	if (ft5x0x_read_reg(ft_g_client, 0x00, &regval) < 0) {
		pr_err("%s ERROR: could not read register\n", __FUNCTION__);
		return -EPERM;
	}

	if ((regval & 0x70) != 0x40) {
		pr_err("%s ERROR:Touch Panel put in Factory Mode err. Mode reg: 0x%02X\n", __func__, regval);
		return -EPERM;
	}

	return 0;
}

static int ft5x0x_enter_work(void)
{
	u8 regval;
	ft5x0x_write_reg(ft_g_client, 0x00, 0x00);
	msleep(100);

	if (ft5x0x_read_reg(ft_g_client, 0x00, &regval) < 0) {
		pr_err("%s ERROR: could not read register\n", __FUNCTION__);
		return -EPERM;
	}

	if ((regval & 0x70) != 0x00) {
		pr_err("%s ERROR:Touch Panel put in Work Mode err. Mode reg: 0x%02X\n", __func__, regval);
		return -EPERM;
	}

	return 0;
}


static int ft5x0x_read_rawdata(u16 rawdata[][FTS_RX_MAX],
			u8 tx, u8 rx)
{
	u8 i = 0, j = 0, k = 0;
	int err = 0;
	u8 regvalue = 0x00;
	u8 regaddr = 0x00;
	u16 dataval = 0x0000;
	u8 writebuf[2] = {0};
	u8 read_buffer[FTS_RX_MAX * 2];
	/*scan*/
	err = ft5x0x_read_reg(ft_g_client, FTS_DEVICE_MODE_REG, &regvalue);
	if (err < 0)
		return err;

	regvalue |= 0x80;
	err = ft5x0x_write_reg(ft_g_client, FTS_DEVICE_MODE_REG, regvalue);
	if (err < 0)
		return err;

	for (i = 0; i < 20; i++) {
		msleep(8);
		err = ft5x0x_read_reg(ft_g_client, FTS_DEVICE_MODE_REG,
					&regvalue);
		if (err < 0)
			return err;

		if (0 == (regvalue >> 7))
			break;
	}

	/*get rawdata*/

	for (i = 0; i < tx; i++) {
		memset(read_buffer, 0x00, (FTS_RX_MAX * 2));
		writebuf[0] = FTS_RAW_READ_REG;
		writebuf[1] = i;
		err = ft5435_i2c_write(ft_g_client, writebuf, 2);
		if (err < 0) {
			return err;
		}
		/* Read the data for this row */
		regaddr = FTS_RAW_BEGIN_REG;
		err = ft5435_i2c_read(ft_g_client, &regaddr, 1, read_buffer, rx*2);
		if (err < 0) {
			return err;
		}

		k = 0;
		for (j = 0; j < rx*2; j += 2) {
			dataval  = read_buffer[j];
			dataval  = (dataval << 8);
			dataval |= read_buffer[j+1];
			rawdata[i][k] = dataval;
			k++;
		}
	}

	return 0;
}

static int fts_get_channel_info(u8 *rx, u8 *tx)
{
	/*get rx and tx num*/
	if (ft5x0x_read_reg(ft_g_client, 0x02, tx) < 0) {
		printk("%s: get tx info err!\n", __func__);
		return -EPERM;
	}

	if (ft5x0x_read_reg(ft_g_client, 0x03, rx) < 0) {
		printk("%s: get rx info err!\n", __func__);
		return -EPERM;
	}

	return 0;
}

static u16 g_rawdata[FTS_TX_MAX][FTS_RX_MAX];
static ssize_t ft5435_rawdata_register(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     char *buf)
{
	struct ft5435_ts_data *data = i2c_get_clientdata(ft_g_client);
	int i, j, p = 0;
	u8 rx, tx;
	int ret;

printk("ft5435_rawdata_register: start\n");
	mutex_lock(&data->input_dev->mutex);
	if (data->loading_fw) {
		p = sprintf(buf+p, "loading fw!!!");
		goto RAW_ERROR;
	}

	data->loading_fw = true;
	if (ft5x0x_enter_factory()) {
		p = sprintf(buf+p, "enter factory mode err!!!");
		goto RAW_ERROR;
	}

	if (fts_get_channel_info(&rx, &tx)) {
		p = sprintf(buf+p, "read channel info error!!\n");
		goto RAW_ERROR;
	}

/*[BUGFIX] ADD BEGIN - hui.wang,2014/03/17 PR-618021 To get the params*/
	p += sprintf(buf+p, "tp channel: tx = %u, rx = %u\n", tx, rx);
/*[BUGFIX] ADD END - hui.wang,2014/03/17 PR-618021 To get the params*/

	ret = ft5x0x_read_rawdata(g_rawdata, tx, rx);

	if (ret < 0) {
		p = sprintf(buf+p, "rawdata read error!\n");
		goto RAW_ERROR;
	}

	for (i = 0; i < tx; i++) {
		for (j = 0; j < rx; j++) {
			p += sprintf(buf+p, "%u ", g_rawdata[i][j]);
		}
		p += sprintf(buf+p, "\n");
	}

RAW_ERROR:
	/*enter work mode*/
	data->loading_fw = false;
	if (ft5x0x_enter_work())
		p = sprintf(buf+p, "enter work mode error!!\n");
	msleep(100);
	mutex_unlock(&data->input_dev->mutex);
	return p;
}
static ssize_t rd_result_show (struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	char *s = buf;
	int i;


	s += sprintf(s, "**************************\nAA Zone:");

	if (rawdata_fail_num == 0) {
		s += sprintf(s, "PASS\n");
	} else  {
		s += sprintf(s, "NG\n");
		for (i = 0; i < rawdata_fail_num; i++) {
			if (ft5436_rawdata_test_result.index[i][1] < 25) {
				s += sprintf(s, "X%dY%d(%u)\n", ft5436_rawdata_test_result.index[i][0],
							ft5436_rawdata_test_result.index[i][1],
							ft5436_rawdata_test_result.index[i][2]);
			}
		}
	}
	s += sprintf(s, "Min: %u  Max: %u\n", ft5436_rawdata_test_result.min_value, ft5436_rawdata_test_result.max_value);
	s += sprintf(s, "Spec Min: %u  Max: %u\n", ft5436_rawdata_test_result.min_limited_value, ft5436_rawdata_test_result.max_limited_value);


	s += sprintf(s, "**************************\nKey Zone:");
	if (rawdata_fail_num == 0) {
		s += sprintf(s, "PASS\n");
	} else {
		s += sprintf(s, "NG\n");
	}
	s += sprintf(s, "Spec Min: %u  Max: %u\n", ft5436_rawdata_test_result.min_limited_value, ft5436_rawdata_test_result.max_limited_value);
	s += sprintf(s, "**************************\n");

	return (s-buf);
}


static ssize_t jrd_ic_info_show (struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	u8 reg_ver;
	u8 reg_vendor;
	u8 ver_value, vendor_value;
	int err;
	char *ret = buf;

	reg_ver = FT_REG_FW_VER;
	err = ft5435_i2c_read(ft_g_client, &reg_ver, 1, &ver_value, 1);
	if (err < 0) {
		 pr_err("TP FW version read failure\n");
		 return sprintf (buf, "can't read firmware version \n");
	}
	pr_err("0xA6=0x%x\n", ver_value);
	reg_vendor = 0xA8;
	err = ft5435_i2c_read(ft_g_client, &reg_vendor, 1, &vendor_value, 1);
	if (err < 0) {
		pr_err("TP FW version read failure\n");
		return sprintf (buf, "ft irmware version(0xA6) is 0x%x\n can't read tp moudule  version \n" , ver_value);
	}
	pr_err("0xA8=0x%x\n", vendor_value);

	ret += sprintf(ret, "%s", "TP IC: FT5436\n");
	ret += sprintf(ret, "TP module (0xA8) is 0x%x\n", vendor_value);
	ret += sprintf(ret, "fimware version (0xA6) is 0x%x\n", ver_value);
	return (ret - buf);
}

static struct kobj_attribute ft5435_rawdata_attr = {
	.attr = {
		.name = "ft5435_rawdata",
		.mode = S_IRUGO,
	},
	.show = &ft5435_rawdata_register,
};

static struct kobj_attribute rd_result = {
	.attr = {
		.name = "rd_result",
		.mode = S_IRUGO,
	},
	.show = &rd_result_show,
};

static struct kobj_attribute ft5435_ic_info_attr = {
	.attr = {
		.name = "jrd_tp_ic_info",
		.mode = S_IRUGO,
	},
	.show = &jrd_ic_info_show,
};

static struct attribute *ft5435_rawdata_properties_attrs[] = {
	&ft5435_rawdata_attr.attr,
	&rd_result.attr,
	&ft5435_ftsscaptest_attr.attr,
	&ft5435_ic_info_attr.attr,
	NULL,
};
static struct attribute_group ft5435_rawdata_properties_attr_group = {
	.attrs = ft5435_rawdata_properties_attrs,
};
#endif

#if defined(CONFIG_TCT_TP_FTDEBUG)
#define FTS_PACKET_LENGTH        128
#define PROC_UPGRADE              	0
#define PROC_READ_REGISTER          	1
#define PROC_WRITE_REGISTER        	2
#define PROC_AUTOCLB                	4
#define PROC_UPGRADE_INFO           	5
#define PROC_WRITE_DATA               	6
#define PROC_READ_DATA                 	7

#define PROC_NAME    "ft5x0x-debug"
static unsigned char proc_operate_mode = PROC_UPGRADE;
static struct proc_dir_entry *ft5x0x_proc_entry;


/*interface of write proc*/
static ssize_t ft5x0x_debug_write(struct file *filp, const char __user *buffer, size_t count, loff_t *off)
{
	struct i2c_client *client = ft_g_client;
	unsigned char writebuf[FTS_PACKET_LENGTH];
	int buflen = count;
	int writelen = 0;
	int ret = 0;

	if (copy_from_user(writebuf, (void __user *)buffer, buflen)) {
		dev_err(&client->dev, "%s:copy from user error\n", __func__);
		return -EFAULT;
	}

	proc_operate_mode = writebuf[0];
	printk("proc_operate_mode = %d\n", proc_operate_mode);
	switch (proc_operate_mode) {
	case PROC_READ_REGISTER:
	printk("%s, %d:PROC_READ_REGISTER\n", __func__, __LINE__);
		writelen = 1;
		ret = ft5435_i2c_write(client, writebuf + 1, writelen);
		if (ret < 0) {
			dev_err(&client->dev, "%s:write iic error\n", __func__);
			return ret;
		}
		break;
	case PROC_WRITE_REGISTER:
	printk("%s, %d:PROC_WRITE_REGISTER\n", __func__, __LINE__);
		writelen = 2;
		ret = ft5435_i2c_write(client, writebuf + 1, writelen);
		if (ret < 0) {
			dev_err(&client->dev, "%s:write iic error\n", __func__);
			return ret;
		}
		break;
	case PROC_AUTOCLB:
	printk("%s, %d:PROC_AUTOCLB\n", __func__, __LINE__);
		printk("%s: autoclb\n", __func__);
		fts_ctpm_auto_clb(client);
		break;
	case PROC_READ_DATA:
	case PROC_WRITE_DATA:
	printk("%s, %d:PROC_READ_DATA, PROC_WRITE_DATA\n", __func__, __LINE__);
		writelen = count - 1;
		ret = ft5435_i2c_write(client, writebuf + 1, writelen);
		if (ret < 0) {
			dev_err(&client->dev, "%s:write iic error\n", __func__);
		      return ret;
		}
		break;
	default:
	printk("%s, %d:default\n", __func__, __LINE__);
		break;
	}

	return count;
}

/*interface of read proc*/
static ssize_t ft5x0x_debug_read(struct file *file, char __user *page, size_t size, loff_t *ppos)
{
	struct i2c_client *client = ft_g_client;
	int ret = 0;
	unsigned char buf[1000];
	int num_read_chars = 0;
	int readlen = 0;
	u8 regvalue = 0x00, regaddr = 0x00;

	switch (proc_operate_mode) {
	case PROC_UPGRADE:
		/*after calling ft5x0x_debug_write to upgrade*/
		printk("%s, %d:PROC_UPGRADE\n", __func__, __LINE__);
		regaddr = 0xA6;
		ret = ft5x0x_read_reg(client, regaddr, &regvalue);
		if (ret < 0)
			num_read_chars = sprintf(buf, "%s", "get fw version failed.\n");
		else
			num_read_chars = sprintf(buf, "current fw version:0x%02x\n", regvalue);
		break;
	case PROC_READ_REGISTER:
		readlen = 1;
		ret = ft5435_i2c_read(client, NULL, 0, buf, readlen);
		if (ret < 0) {
			dev_err(&client->dev, "%s:read iic error\n", __func__);
			return ret;
		}
		printk("%s, %d:PROC_READ_REGISTER, buf = %c\n", __func__, __LINE__, *buf);
		num_read_chars = 1;
		break;
	case PROC_READ_DATA:
		printk("%s, %d:PROC_READ_DATA\n", __func__, __LINE__);
		readlen = size;
		ret = ft5435_i2c_read(client, NULL, 0, buf, readlen);
		if (ret < 0) {
			dev_err(&client->dev, "%s:read iic error\n", __func__);
			return ret;
		}

		num_read_chars = readlen;
		break;
	case PROC_WRITE_DATA:
		printk("%s, %d:PROC_WRITE_DATA\n", __func__, __LINE__);
		break;
	default:
		printk("%s, %d:default\n", __func__, __LINE__);
		break;
	}

	memcpy(page, buf, num_read_chars);

	return num_read_chars;
}

static const struct file_operations ft5x0x_debug_ops = {
	.owner = THIS_MODULE,
	.read = ft5x0x_debug_read,
	.write = ft5x0x_debug_write,
};

static int ft5x0x_create_apk_debug_channel(struct i2c_client *client)
{
	ft5x0x_proc_entry = proc_create(PROC_NAME, 0777, NULL, &ft5x0x_debug_ops);

	if (NULL == ft5x0x_proc_entry) {
		dev_err(&client->dev, "Couldn't create proc entry!\n");
		return -ENOMEM;
	} else {
		dev_info(&client->dev, "Create proc entry success!\n");
	}
	return 0;
}

static void ft5x0x_release_apk_debug_channel(void)
{
	if (ft5x0x_proc_entry)
		remove_proc_entry(PROC_NAME, NULL);
}
#endif

static ssize_t ft5435_ts_disable_keys_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	const char c = disable_keys_function ? '1' : '0';
	return sprintf(buf, "%c\n", c);
}

static ssize_t ft5435_ts_disable_keys_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int i;

	if (sscanf(buf, "%u", &i) == 1 && i < 2) {
		disable_keys_function = (i == 1);
		return count;
	} else {
		dev_dbg(dev, "disable_keys write error\n");
		return -EINVAL;
	}
}


static DEVICE_ATTR(disable_keys, S_IWUSR | S_IRUSR, ft5435_ts_disable_keys_show,
		   ft5435_ts_disable_keys_store);



static ssize_t ft5435_ts_enable_dt2w_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
        const char c = gesture_func_on ? '1' : '0';
        return sprintf(buf, "%c\n", c);
}

static ssize_t ft5435_ts_enable_dt2w_store(struct device *dev,
        struct device_attribute *attr, const char *buf, size_t count)
{
        int i;

        if (sscanf(buf, "%u", &i) == 1 && i < 2) {
                gesture_func_on = (i == 1);
                return count;
        } else {
                dev_dbg(dev, "enable_dt2w write error\n");
                return -EINVAL;
        }
}


static DEVICE_ATTR(enable_dt2w, S_IWUSR | S_IRUSR, ft5435_ts_enable_dt2w_show,
                   ft5435_ts_enable_dt2w_store);

static struct attribute *ft5435_ts_attrs[] = {
    &dev_attr_disable_keys.attr,
    &dev_attr_enable_dt2w.attr,
	NULL
};


static const struct attribute_group ft5435_ts_attr_group = {
       .attrs = ft5435_ts_attrs,
};

static int ft5435_proc_init(struct kernfs_node *sysfs_node_parent)
{
       int ret = 0;
       char *buf;
       char *key_disabler_sysfs_node, *double_tap_sysfs_node;
       struct proc_dir_entry *proc_entry_tp = NULL;
       struct proc_dir_entry *proc_symlink_tmp = NULL;
       buf = kzalloc(PATH_MAX, GFP_KERNEL);
       if (buf)
               kernfs_path(sysfs_node_parent, buf, PATH_MAX);

       proc_entry_tp = proc_mkdir("touchpanel", NULL);
       if (proc_entry_tp == NULL) {
               pr_err("%s: Couldn't create touchpanel dir in procfs\n", __func__);
               ret = -ENOMEM;
       }

       key_disabler_sysfs_node = kzalloc(PATH_MAX, GFP_KERNEL);
       if (key_disabler_sysfs_node)
               sprintf(key_disabler_sysfs_node, "/sys%s/%s", buf, "disable_keys");
       proc_symlink_tmp = proc_symlink("capacitive_keys_disable",
                       proc_entry_tp, key_disabler_sysfs_node);
       if (proc_symlink_tmp == NULL) {
               pr_err("%s: Couldn't create capacitive_keys_enable symlink\n", __func__);
               ret = -ENOMEM;
       }

       double_tap_sysfs_node = kzalloc(PATH_MAX, GFP_KERNEL);
       if (double_tap_sysfs_node)
               sprintf(double_tap_sysfs_node, "/sys%s/%s", buf, "enable_dt2w");
       proc_symlink_tmp = proc_symlink("enable_dt2w",
               proc_entry_tp, double_tap_sysfs_node);
       if (proc_symlink_tmp == NULL) {
               ret = -ENOMEM;
               pr_err("%s: Couldn't create double_tap_enable symlink\n", __func__);
       }

       kfree(buf);
       kfree(key_disabler_sysfs_node);
       kfree(double_tap_sysfs_node);
       return ret;
}

static char tp_info_summary[80] = "";

static int ft5435_ts_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct ft5435_ts_platform_data *pdata;
	struct ft5435_ts_data *data;
	struct input_dev *input_dev;
	struct dentry *temp;
	u8 reg_value;
	u8 reg_addr;
	int err, len;
	u8 w_buf[FT_MAX_WR_BUF] = {0};
	int i;
	int retry = 3;
	char tp_temp_info[80];
	printk("~~~~~ ft5435_ts_probe start\n");

#if defined(CONFIG_FB)
	printk("[%s]CONFIG_FB is defined\n", __FUNCTION__);
#endif
#if defined(CONFIG_PM)
		printk("[%s]CONFIG_PM is defined\n", __FUNCTION__);
#endif

	if (client->dev.of_node) {
		pdata = devm_kzalloc(&client->dev,
			sizeof(struct ft5435_ts_platform_data), GFP_KERNEL);
		if (!pdata) {
			dev_err(&client->dev, "Failed to allocate memory\n");
			return -ENOMEM;
		}

		err = ft5435_parse_dt(&client->dev, pdata);
		if (err) {
			dev_err(&client->dev, "DT parsing failed\n");
			return err;
		}
	} else
		pdata = client->dev.platform_data;

	if (!pdata) {
		dev_err(&client->dev, "Invalid pdata\n");
		return -EINVAL;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "I2C not supported\n");
		return -ENODEV;
	}

	data = devm_kzalloc(&client->dev,
			sizeof(struct ft5435_ts_data), GFP_KERNEL);
	if (!data) {
		dev_err(&client->dev, "Not enough memory\n");
		return -ENOMEM;
	}

	if (pdata->fw_name) {
		len = strlen(pdata->fw_name);
		if (len > FT_FW_NAME_MAX_LEN - 1) {
			dev_err(&client->dev, "Invalid firmware name\n");
			return -EINVAL;
		}

		strlcpy(data->fw_name, pdata->fw_name, len + 1);
	}

	data->tch_data_len = FT_TCH_LEN(pdata->num_max_touches);
	data->tch_data = devm_kzalloc(&client->dev,
				data->tch_data_len, GFP_KERNEL);
	if (!data) {
		dev_err(&client->dev, "Not enough memory\n");
		return -ENOMEM;
	}

	input_dev = input_allocate_device();
	if (!input_dev) {
		dev_err(&client->dev, "failed to allocate input device\n");
		return -ENOMEM;
	}

	ft_g_client = client;
	data->input_dev = input_dev;
	data->client = client;
	data->pdata = pdata;

	input_dev->name = "ft5435_ts";
	input_dev->id.bustype = BUS_I2C;
	input_dev->dev.parent = &client->dev;

	input_set_drvdata(input_dev, data);
	i2c_set_clientdata(client, data);

	__set_bit(EV_KEY, input_dev->evbit);
	__set_bit(EV_ABS, input_dev->evbit);
	__set_bit(BTN_TOUCH, input_dev->keybit);
	__set_bit(INPUT_PROP_DIRECT, input_dev->propbit);

	for (i = 0; i < pdata->num_virkey; i++) {
		input_set_capability(input_dev, EV_KEY,
							pdata->vkeys[i].keycode);
	}
	input_mt_init_slots(input_dev, pdata->num_max_touches, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, pdata->x_min,
			     pdata->x_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, pdata->y_min,
			     pdata->y_max, 0, 0);
#if defined(USB_CHARGE_DETECT)
INIT_WORK(&data->work, ft5435_change_scanning_frq_switch);
#endif

#if defined(LEATHER_COVER)
INIT_WORK(&data->work_cover, ft5435_change_leather_cover_switch);
#endif
#if defined(VR_GLASS)
INIT_WORK(&data->work_vr, ft5435_change_vr_switch);
#endif

#if defined(FOCALTECH_TP_GESTURE)
	keyset_for_tp_gesture(input_dev);
	input_dev->event = ft5435_gesture_switch;
#endif
	err = input_register_device(input_dev);
	if (err) {
		dev_err(&client->dev, "Input device registration failed\n");
		goto free_inputdev;
	}

	if (gpio_is_valid(pdata->reset_gpio)) {
		err = gpio_request(pdata->reset_gpio, "ft5435_reset_gpio");
		if (err) {
			dev_err(&client->dev, "reset gpio request failed");
			goto unreg_inputdev;
		}

		err = gpio_direction_output(pdata->reset_gpio, 0);
		if (err) {
			dev_err(&client->dev,
				"set_direction for reset gpio failed\n");
			goto free_reset_gpio;
		}
		msleep(2);
	}

	if (pdata->power_init) {
		err = pdata->power_init(true);
		if (err) {
			dev_err(&client->dev, "power init failed");
			goto free_reset_gpio;
		}
	} else {
		err = ft5435_power_init(data, true);
		if (err) {
			dev_err(&client->dev, "power init failed");
			goto free_reset_gpio;
		}
	}

	if (pdata->power_on) {
		err = pdata->power_on(true);
		if (err) {
			dev_err(&client->dev, "power on failed");
			goto pwr_deinit;
		}
	} else {
		err = ft5435_power_on(data, true);
		if (err) {
			dev_err(&client->dev, "power on failed");
			goto pwr_deinit;
		}
	}

	msleep(2);

	err = ft5435_ts_pinctrl_init(data);
	if (!err && data->ts_pinctrl) {
		err = ft5435_ts_pinctrl_select(data, true);
		if (err < 0)
			goto pwr_off;
	}

	if (gpio_is_valid(pdata->irq_gpio)) {
		err = gpio_request(pdata->irq_gpio, "ft5435_irq_gpio");
		if (err) {
			dev_err(&client->dev, "irq gpio request failed");
			goto pwr_off;
		}
		err = gpio_direction_input(pdata->irq_gpio);
		if (err) {
			dev_err(&client->dev,
				"set_direction for irq gpio failed\n");
			goto free_irq_gpio;
		}
	}

	if (gpio_is_valid(pdata->reset_gpio)) {
		gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
	}

	/* make sure CTP already finish startup process */
	msleep(data->pdata->soft_rst_dly);

	/* check the controller id */
	reg_addr = FT_REG_ID;
	while (retry--) {
		err = ft5435_i2c_read(client, &reg_addr, 1, &reg_value, 1);
		if (!(err < 0)) {
#ifdef CONFIG_MACH_XIAOMI_MIDO
			set_usb_charge_mode_par = 2;
#endif
			dev_info(&client->dev, "Device ID = 0x%x\n", reg_value);
			break;
		}
		if (gpio_is_valid(pdata->reset_gpio)) {
			gpio_set_value_cansleep(data->pdata->reset_gpio, 0);
			msleep(10);
			gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
			msleep(200);
		}
		if (retry == 0) {
			dev_err(&client->dev, "version read failed");
			goto free_irq_gpio;
		}
	}
	data->family_id = pdata->family_id;


#ifdef CONFIG_TOUCHPANEL_PROXIMITY_SENSOR
	vps_ft5436 = kzalloc(sizeof(struct virtualpsensor), GFP_KERNEL);
	if (!vps_ft5436) {
		dev_err(&client->dev, "Not enough memory\n");
		return -ENOMEM;
	}
	virtual_psensor_input_register2(client) ;
	sys_device_create();
#endif


	mutex_init(&g_device_mutex);

#if defined(FOCALTECH_PWRON_UPGRADE)
	err = ft_init_update_proc(data);
	if (err < 0) {
		dev_err(&client->dev,
				"GTP Create firmware update thread error.\n");

	}
#endif
	err = request_threaded_irq(client->irq, NULL,
				ft5435_ts_interrupt,
				pdata->irqflags | IRQF_ONESHOT|IRQF_TRIGGER_FALLING,
				client->dev.driver->name, data);
	if (err) {
		dev_err(&client->dev, "request irq failed\n");
		goto free_reset_gpio;
	}

	INIT_DELAYED_WORK(&data->resume_work, ft5435_resume_func);
	ft5435_resume_workqueue = create_workqueue("fts_resume_wq");

	err = device_create_file(&client->dev, &dev_attr_fw_name);
	if (err) {
		dev_err(&client->dev, "sys file creation failed\n");
		goto irq_free;
	}

	err = device_create_file(&client->dev, &dev_attr_fw_version);
	if (err) {
		dev_err(&client->dev, "sys file creation failed\n");
		goto free_fw_name_sys;
	}

	err = device_create_file(&client->dev, &dev_attr_update_fw);
	if (err) {
		dev_err(&client->dev, "sys file creation failed\n");
		goto free_fw_version_sys;
	}

	err = device_create_file(&client->dev, &dev_attr_force_update_fw);
	if (err) {
		dev_err(&client->dev, "sys file creation failed\n");
		goto free_update_fw_sys;
	}
#ifdef SET_COVER_MODE
	err = device_create_file(&client->dev, &dev_attr_set_cover_mode);
	if (err) {
		dev_err(&client->dev, "sys file creation failed\n");
		goto free_set_cover_mode;
	}
#endif
	data->dir = debugfs_create_dir(FT_DEBUG_DIR_NAME, NULL);
	if (data->dir == NULL || IS_ERR(data->dir)) {
		pr_err("debugfs_create_dir failed(%ld)\n", PTR_ERR(data->dir));
		err = PTR_ERR(data->dir);
		goto free_force_update_fw_sys;
	}

	temp = debugfs_create_file("addr", S_IRUSR | S_IWUSR, data->dir, data,
				   &debug_addr_fops);
	if (temp == NULL || IS_ERR(temp)) {
		pr_err("debugfs_create_file failed: rc=%ld\n", PTR_ERR(temp));
		err = PTR_ERR(temp);
		goto free_debug_dir;
	}

	temp = debugfs_create_file("data", S_IRUSR | S_IWUSR, data->dir, data,
				   &debug_data_fops);
	if (temp == NULL || IS_ERR(temp)) {
		pr_err("debugfs_create_file failed: rc=%ld\n", PTR_ERR(temp));
		err = PTR_ERR(temp);
		goto free_debug_dir;
	}

	temp = debugfs_create_file("suspend", S_IRUSR | S_IWUSR, data->dir,
					data, &debug_suspend_fops);
	if (temp == NULL || IS_ERR(temp)) {
		pr_err("debugfs_create_file failed: rc=%ld\n", PTR_ERR(temp));
		err = PTR_ERR(temp);
		goto free_debug_dir;
	}

	temp = debugfs_create_file("dump_info", S_IRUSR | S_IWUSR, data->dir,
					data, &debug_dump_info_fops);
	if (temp == NULL || IS_ERR(temp)) {
		pr_err("debugfs_create_file failed: rc=%ld\n", PTR_ERR(temp));
		err = PTR_ERR(temp);
		goto free_debug_dir;
	}

	data->ts_info = devm_kzalloc(&client->dev,
				FT_INFO_MAX_LEN, GFP_KERNEL);
	if (!data->ts_info) {
		dev_err(&client->dev, "Not enough memory\n");
		goto free_debug_dir;
	}

	/*get some register information */
	reg_addr = FT_REG_POINT_RATE;
	ft5435_i2c_read(client, &reg_addr, 1, &reg_value, 1);
	if (err < 0)
		dev_err(&client->dev, "report rate read failed");

	dev_info(&client->dev, "report rate = %dHz\n", reg_value * 10);

	reg_addr = FT_REG_THGROUP;
	err = ft5435_i2c_read(client, &reg_addr, 1, &reg_value, 1);
	if (err < 0)
		dev_err(&client->dev, "threshold read failed");

	dev_dbg(&client->dev, "touch threshold = %d\n", reg_value * 4);

	ft5435_update_fw_ver(data);
	ft5435_update_fw_vendor_id(data);
	fts_fw_vendor_id = data->fw_vendor_id;
	printk("upgrade,fts_fw_vendor_id=0x%02x\n",  data->fw_vendor_id);
#if defined(FOCALTECH_AUTO_UPGRADE)
	if ((fts_fw_vendor_id != FTS_VENDOR_1) && (fts_fw_vendor_id != FTS_VENDOR_2) && (fts_fw_vendor_id != FTS_VENDOR_3)) {
		fts_fw_vendor_id = ft5435_fw_Vid_get_from_boot(client);
		printk("get_Vid_from_boot, fw_vendor_id=0x%02x\n",  fts_fw_vendor_id);
	}

	mutex_lock(&data->input_dev->mutex);
	if (!data->loading_fw) {
		data->loading_fw = true;
		if (fts_fw_vendor_id == FTS_VENDOR_1)
			ft5435_fw_upgrade_by_array_data(&client->dev, firmware_data_vendor1, sizeof(firmware_data_vendor1), !data->pdata->no_force_update);
		else if (fts_fw_vendor_id == FTS_VENDOR_2)
			ft5435_fw_upgrade_by_array_data(&client->dev, firmware_data_vendor2, sizeof(firmware_data_vendor2), !data->pdata->no_force_update);
                else if (fts_fw_vendor_id == FTS_VENDOR_3)
                        ft5435_fw_upgrade_by_array_data(&client->dev, firmware_data_vendor3, sizeof(firmware_data_vendor3), !data->pdata->no_force_update);
		else
			printk("[FTS] FW unmatched,stop upgrade\n");
		data->loading_fw = false;
	}
	mutex_unlock(&data->input_dev->mutex);

#endif

	FT_STORE_TS_INFO(data->ts_info, data->family_id, data->pdata->name,
			data->pdata->num_max_touches, data->pdata->group_id,
			data->pdata->fw_vkey_support ? "yes" : "no",
			data->pdata->fw_name, data->fw_ver[0],
			data->fw_ver[1], data->fw_ver[2]);

#if defined(CONFIG_FB)

	data->fb_notif.notifier_call = fb_notifier_callback;

	err = fb_register_client(&data->fb_notif);

	if (err)
		dev_err(&client->dev, "Unable to register fb_notifier: %d\n",
			err);
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	data->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN +
						    FT_SUSPEND_LEVEL;
	data->early_suspend.suspend = ft5435_ts_early_suspend;
	data->early_suspend.resume = ft5435_ts_late_resume;
	register_early_suspend(&data->early_suspend);
#endif


/* [PLATFORM]-Mod-BEGIN by TCTNB.ZXZ, PR-814306, 2014/10/24, add for alto5 premium firmware version*/
#ifdef CONFIG_TCT_8X16_ALTO5_PREMIUM
firm_ver_attr_create();
#endif
/* [PLATFORM]-Mod-END by TCTNB.ZXZ*/

#ifdef FOCALTECH_TP_GLOVE
	tp_glove_register(data);
#endif


g_ft5435_ts_data = data;


#if defined(RAWDATA_INTERFACE)
{
	static struct kobject *ft5435_rawdata_properties_kobj;
	static struct kobject *ft5435_CTP_properties_kobj;
	int rc = 0;

	ft5435_rawdata_properties_kobj =
		kobject_create_and_add("rawdata", NULL);

	if (ft5435_rawdata_properties_kobj)
		rc = sysfs_create_group(ft5435_rawdata_properties_kobj,
		&ft5435_rawdata_properties_attr_group);

	if (!ft5435_rawdata_properties_kobj || rc)
		pr_err("%s: failed to create rawdata\n", __func__);

	ft5435_CTP_properties_kobj =
		kobject_create_and_add("CTP", NULL);

	if (ft5435_CTP_properties_kobj)
		rc = sysfs_create_group(ft5435_CTP_properties_kobj,
			&ft5435_rawdata_properties_attr_group);

	if (!ft5435_CTP_properties_kobj || rc)
		pr_err("%s: failed to create rawdata\n", __func__);
}
#endif
#ifdef FOCALTECH_LOCK_DOWN_INFO
		ft5435_fw_LockDownInfo_get_from_boot(client, tp_lockdown_info);
		printk("tpd_probe, ft5x46_ctpm_LockDownInfo_get_from_boot, tp_lockdown_info=%s\n", tp_lockdown_info);
		ctp_lockdown_status_proc = proc_create(CTP_PROC_LOCKDOWN_FILE, 0644, NULL, &ctp_lockdown_proc_fops);
		if (ctp_lockdown_status_proc == NULL)
			printk("tpd, create_proc_entry ctp_lockdown_status_proc failed\n");
#endif

#if defined(CONFIG_TCT_TP_FTDEBUG)
	if (ft5x0x_create_apk_debug_channel(client) < 0)
		ft5x0x_release_apk_debug_channel();
#endif
        err = sysfs_create_group(&client->dev.kobj, &ft5435_ts_attr_group);
        if (err) {
	        dev_err(&client->dev, "Failure %d creating sysfs group\n",
		        err);
                goto free_reset_gpio;
        }
	ft5435_proc_init(client->dev.kobj.sd);

	w_buf[0] = FT_REG_RESET_FW;
	ft5435_i2c_write(client, w_buf, 1);
	init_ok = 1;
	wakeup_source_init(&ft5436_wakelock, "ft5436");
	if (fts_fw_vendor_id == FTS_VENDOR_1) {
		strcpy(tp_info_summary, "[Vendor]Biel, [IC]FT5435, [FW]Ver");
	} else if (fts_fw_vendor_id == FTS_VENDOR_2) {
		strcpy(tp_info_summary, "[Vendor]Ofilm, [IC]FT5435, [FW]Ver");
	} else{
		strcpy(tp_info_summary, "[Vendor]Unknown, [IC]FT5435, [FW]Ver");
	}
	sprintf(tp_temp_info, "%d", data->fw_ver[0]);
	strcat(tp_info_summary, tp_temp_info);
	strcat(tp_info_summary, "\0");
	printk("~~~~~ ft5435_ts_probe end\n");
	return 0;

free_debug_dir:
	debugfs_remove_recursive(data->dir);
free_force_update_fw_sys:
	device_remove_file(&client->dev, &dev_attr_force_update_fw);
free_update_fw_sys:
	device_remove_file(&client->dev, &dev_attr_update_fw);

#ifdef SET_COVER_MODE
free_set_cover_mode:
	device_remove_file(&client->dev, &dev_attr_set_cover_mode);
#endif

free_fw_version_sys:
	device_remove_file(&client->dev, &dev_attr_fw_version);

free_fw_name_sys:
	device_remove_file(&client->dev, &dev_attr_fw_name);
irq_free:
	free_irq(client->irq, data);

free_irq_gpio:
	if (gpio_is_valid(pdata->irq_gpio))
		gpio_free(pdata->irq_gpio);
	if (data->ts_pinctrl) {
		err = ft5435_ts_pinctrl_select(data, false);
		if (err < 0)
			pr_err("Cannot get idle pinctrl state\n");
	}
	if (data->ts_pinctrl) {
			devm_pinctrl_put(data->ts_pinctrl);
			data->ts_pinctrl = NULL;
	}
	if (gpio_is_valid(pdata->reset_gpio)) {
		gpio_direction_output(pdata->reset_gpio, 0);
		mdelay(2);
	}
pwr_off:
	if (pdata->power_on)
		pdata->power_on(false);
	else
		ft5435_power_on(data, false);
pwr_deinit:
	if (pdata->power_init)
		pdata->power_init(false);
	else
		ft5435_power_init(data, false);
free_reset_gpio:
	if (gpio_is_valid(pdata->reset_gpio)) {
		gpio_direction_output(pdata->reset_gpio, 0);
		mdelay(5);
		gpio_free(pdata->reset_gpio);
		}
unreg_inputdev:
	input_unregister_device(input_dev);
	input_dev = NULL;
free_inputdev:
	input_free_device(input_dev);
	return err;
}

static int ft5435_ts_remove(struct i2c_client *client)
{
	struct ft5435_ts_data *data = i2c_get_clientdata(client);
	int retval;

	debugfs_remove_recursive(data->dir);
	device_remove_file(&client->dev, &dev_attr_force_update_fw);
	device_remove_file(&client->dev, &dev_attr_update_fw);
	device_remove_file(&client->dev, &dev_attr_fw_name);

#if defined(CONFIG_FB)
	if (fb_unregister_client(&data->fb_notif))
		dev_err(&client->dev, "Error occurred while unregistering fb_notifier.\n");
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&data->early_suspend);
#endif
	free_irq(client->irq, data);

	if (gpio_is_valid(data->pdata->reset_gpio))
		gpio_free(data->pdata->reset_gpio);

	if (gpio_is_valid(data->pdata->irq_gpio))
		gpio_free(data->pdata->irq_gpio);

	if (data->ts_pinctrl) {
		retval = ft5435_ts_pinctrl_select(data, false);
		if (retval < 0)
			pr_err("Cannot get idle pinctrl state\n");
		devm_pinctrl_put(data->ts_pinctrl);
		data->ts_pinctrl = NULL;
	}

	if (data->pdata->power_on)
		data->pdata->power_on(false);
	else
		ft5435_power_on(data, false);

	if (data->pdata->power_init)
		data->pdata->power_init(false);
	else
		ft5435_power_init(data, false);


#if defined(CONFIG_TCT_TP_FTDEBUG)
	ft5x0x_release_apk_debug_channel();
#endif

	input_unregister_device(data->input_dev);
	wakeup_source_trash(&ft5436_wakelock);

	return 0;
}

static const struct i2c_device_id ft5435_ts_id[] = {
	{"ft5435_ts", 0},
	{},
};

MODULE_DEVICE_TABLE(i2c, ft5435_ts_id);

#ifdef CONFIG_OF
static struct of_device_id ft5435_match_table[] = {
	{ .compatible = "focaltech,5435",},
	{ },
};
#else
#define ft5435_match_table NULL
#endif

static struct i2c_driver ft5435_ts_driver = {
	.probe = ft5435_ts_probe,
	.remove = ft5435_ts_remove,
	.driver = {
		   .name = "ft5435_ts",
		   .owner = THIS_MODULE,
		.of_match_table = ft5435_match_table,
#ifdef CONFIG_PM
		   .pm = &ft5435_ts_pm_ops,
#endif
		   },
	.id_table = ft5435_ts_id,
};

static int __init ft5435_ts_init(void)
{
	printk("tony_test:[%s]\n", __FUNCTION__);
	ft5435_wq = create_singlethread_workqueue("ft5435_wq");
	if (!ft5435_wq) {
		printk("Creat ft5435 workqueue failed. \n");
		return -ENOMEM;
	}
	ft5435_wq_cover = create_singlethread_workqueue("ft5435_wq_cover");
	if (!ft5435_wq_cover) {
		printk("Creat ft5435_wq_cover workqueue failed. \n");
		return -ENOMEM;
	}
#if defined(VR_GLASS)
	ft5435_wq_vr = create_singlethread_workqueue("ft5435_wq_vr");
	if (!ft5435_wq_vr) {
		printk("Creat ft5435_wq_vr workqueue failed. \n");
		return -ENOMEM;
	}
#endif
	return i2c_add_driver(&ft5435_ts_driver);
}
module_init(ft5435_ts_init);

static void __exit ft5435_ts_exit(void)
{
	if (ft5435_wq) {
		destroy_workqueue(ft5435_wq);
	}
	i2c_del_driver(&ft5435_ts_driver);
}
module_exit(ft5435_ts_exit);

MODULE_DESCRIPTION("FocalTech ft5435 TouchScreen driver");
MODULE_LICENSE("GPL v2");
