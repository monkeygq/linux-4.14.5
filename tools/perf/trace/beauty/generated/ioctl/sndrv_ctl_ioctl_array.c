static const char *sndrv_ctl_ioctl_cmds[] = {
	[0x00] = "PVERSION",
	[0x01] = "CARD_INFO",
	[0x10] = "ELEM_LIST",
	[0x11] = "ELEM_INFO",
	[0x12] = "ELEM_READ",
	[0x13] = "ELEM_WRITE",
	[0x14] = "ELEM_LOCK",
	[0x15] = "ELEM_UNLOCK",
	[0x16] = "SUBSCRIBE_EVENTS",
	[0x17] = "ELEM_ADD",
	[0x18] = "ELEM_REPLACE",
	[0x19] = "ELEM_REMOVE",
	[0x1a] = "TLV_READ",
	[0x1b] = "TLV_WRITE",
	[0x1c] = "TLV_COMMAND",
	[0x20] = "HWDEP_NEXT_DEVICE",
	[0x21] = "HWDEP_INFO",
	[0x30] = "PCM_NEXT_DEVICE",
	[0x31] = "PCM_INFO",
	[0x32] = "PCM_PREFER_SUBDEVICE",
	[0x40] = "RAWMIDI_NEXT_DEVICE",
	[0x41] = "RAWMIDI_INFO",
	[0x42] = "RAWMIDI_PREFER_SUBDEVICE",
	[0xd0] = "POWER",
	[0xd1] = "POWER_STATE",
};
