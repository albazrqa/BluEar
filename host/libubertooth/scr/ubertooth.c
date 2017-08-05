/*
 * Copyright 2016 Wahhab Albazrqaoe
 *
 * This file is part of Project BlueEar.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include "ubertooth.h"
#include "math.h"


#ifdef USE_PCAP
#include <pcap.h>
pcap_t *pcap_dumpfile = NULL;
pcap_dumper_t *dumper = NULL;

// CACE PPI headers
#define PPI_BTLE	30006

typedef struct ppi_packetheader {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((packed)) ppi_packet_header_t;

typedef struct ppi_fieldheader {
	u_int16_t pfh_type;       /* Type */
	u_int16_t pfh_datalen;    /* Length of data */
} ppi_fieldheader_t;

typedef struct ppi_btle {
	uint8_t btle_version; // 0 for now
	uint16_t btle_channel;
	uint8_t btle_clkn_high;
	uint32_t btle_clk100ns;
	int8_t rssi_max;
	int8_t rssi_min;
	int8_t rssi_avg;
	uint8_t rssi_count;
} __attribute__((packed)) ppi_btle_t;
#endif


void stop_transfers(int sig) {
	sig = sig; // Unused parameter
	stop_ubertooth = 1;
}

void set_timeout(int seconds) {
	/* Upon SIGALRM, call stop_transfers() */
	if (signal(SIGALRM, stop_transfers) == SIG_ERR) {
	  perror("Unable to catch SIGALRM");
	  exit(1);
	}
	alarm(seconds);
}

static struct libusb_device_handle* find_ubertooth_device(int ubertooth_device)
{
	struct libusb_context *ctx = NULL;
	struct libusb_device **usb_list = NULL;
	struct libusb_device_handle *devh = NULL;
	struct libusb_device_descriptor desc;
	int usb_devs, i, r, ret, ubertooths = 0;
	int ubertooth_devs[] = {0,0,0,0,0,0,0,0};

	usb_devs = libusb_get_device_list(ctx, &usb_list);
	for(i = 0 ; i < usb_devs ; ++i) {
		r = libusb_get_device_descriptor(usb_list[i], &desc);
		if(r < 0)
			fprintf(stderr, "couldn't get usb descriptor for dev #%d!\n", i);
		if ((desc.idVendor == TC13_VENDORID && desc.idProduct == TC13_PRODUCTID)
			|| (desc.idVendor == U0_VENDORID && desc.idProduct == U0_PRODUCTID)
			|| (desc.idVendor == U1_VENDORID && desc.idProduct == U1_PRODUCTID))
		{
			ubertooth_devs[ubertooths] = i;
			ubertooths++;
		}
	}
	if(ubertooths == 1) { 
		ret = libusb_open(usb_list[ubertooth_devs[0]], &devh);
		if (ret)
			show_libusb_error(ret);
	}
	else if (ubertooths == 0)
		return NULL;
	else {
		if (ubertooth_device < 0) {
			fprintf(stderr, "multiple Ubertooth devices found! Use '-U' to specify device number\n");
			u8 serial[17], r;
			for(i = 0 ; i < ubertooths ; ++i) {
				libusb_get_device_descriptor(usb_list[ubertooth_devs[i]], &desc);
				ret = libusb_open(usb_list[ubertooth_devs[i]], &devh);
				if (ret) {
					fprintf(stderr, "  Device %d: ", i);
					show_libusb_error(ret);
				}
				else {
					r = cmd_get_serial(devh, serial);
					if(r==0) {
						fprintf(stderr, "  Device %d: ", i);
						print_serial(serial, stderr);
					}
					libusb_close(devh);
				}
			}
			devh = NULL;
		} else {
			ret = libusb_open(usb_list[ubertooth_devs[ubertooth_device]], &devh);
			if (ret) {
					show_libusb_error(ret);
					devh = NULL;
				}
		}
	}
	return devh;
}


/*
 * based on http://libusb.sourceforge.net/api-1.0/group__asyncio.html#ga9fcb2aa23d342060ebda1d0cf7478856
 */
static void rx_xfer_status(int status)
{
	char *error_name = "";

	switch (status) {
		case LIBUSB_TRANSFER_ERROR:
			error_name="Transfer error.";
			break;
		case LIBUSB_TRANSFER_TIMED_OUT:
			error_name="Transfer timed out.";
			break;
		case LIBUSB_TRANSFER_CANCELLED:
			error_name="Transfer cancelled.";
			break;
		case LIBUSB_TRANSFER_STALL:
			error_name="Halt condition detected, or control request not supported.";
			break;
		case LIBUSB_TRANSFER_NO_DEVICE:
			error_name="Device disconnected.";
			break;
		case LIBUSB_TRANSFER_OVERFLOW:
			error_name="Device sent more data than requested.";
			break;
	}
	fprintf(stderr,"rx_xfer status: %s (%d)\n",error_name,status);
}

static void cb_xfer(struct libusb_transfer *xfer)
{
	int r;
	uint8_t *tmp;

	if (xfer->status != LIBUSB_TRANSFER_COMPLETED) {
		rx_xfer_status(xfer->status);
		libusb_free_transfer(xfer);
		rx_xfer = NULL;
		return;
	}

	while (really_full) {
		/* If we've been killed, the buffer will never get emptied */
		if(stop_ubertooth)
			return;
		fprintf(stderr, "uh oh, full_buf not emptied\n");
	}

	tmp = full_buf;
	full_buf = empty_buf;
	empty_buf = tmp;
	really_full = 1;

	rx_xfer->buffer = empty_buf;

	while (usb_retry) {
		r = libusb_submit_transfer(rx_xfer);
		if (r < 0)
			fprintf(stderr, "rx_xfer submission from callback: %d\n", r);
		else
			break;
	}
}

int handle_events_wrapper() {
	int r = LIBUSB_ERROR_INTERRUPTED;
	while (r == LIBUSB_ERROR_INTERRUPTED) {
		r = libusb_handle_events(NULL);
		if (r < 0) {
			if (r != LIBUSB_ERROR_INTERRUPTED) {
				show_libusb_error(r);
				return -1;
			}
		} else
			return r;
	}
	return 0;
}

int stream_rx_usb(struct libusb_device_handle* devh, int xfer_size,
		uint16_t num_blocks, rx_callback cb, void* cb_args)
{
	int r;
	int i;
	int xfer_blocks;
	int num_xfers;
	usb_pkt_rx* rx;
	uint8_t bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE];
	uint8_t rx_buf2[BUFFER_SIZE];

	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	/*
	fprintf(stderr, "rx %d blocks of 64 bytes in %d byte transfers\n",
		num_blocks, xfer_size);
	*/

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;
	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_rx_syms(devh, num_blocks);

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) {
		fprintf(stderr, "rx_xfer submission: %d\n", r);
		return -1;
	}

	while (1) {
		while (!really_full) {
			handle_events_wrapper();
		}

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) {
			rx = (usb_pkt_rx *)(full_buf + PKT_LEN * i);
			if(rx->pkt_type != KEEP_ALIVE) 
				(*cb)(cb_args, rx, bank);
			bank = (bank + 1) % NUM_BANKS;
			if(stop_ubertooth) {
				stop_ubertooth = 0;
				really_full = 0;
				usb_retry = 0;
				handle_events_wrapper();
				usb_retry = 1;
				return 1;
			}
		}
		really_full = 0;
		fflush(stderr);
	}
}

/* file should be in full USB packet format (ubertooth-dump -f) */
int stream_rx_file(FILE* fp, uint16_t num_blocks, rx_callback cb, void* cb_args)
{
	uint8_t bank = 0;
	uint8_t buf[BUFFER_SIZE];
	size_t nitems;

	UNUSED(num_blocks);

        /*
	fprintf(stderr, "reading %d blocks of 64 bytes from file\n", num_blocks);
	*/

	while(1) {
		uint32_t systime_be;
		nitems = fread(&systime_be, sizeof(systime_be), 1, fp);
		if (nitems != 1)
			return 0;
		systime = (time_t)be32toh(systime_be);

		nitems = fread(buf, sizeof(buf[0]), PKT_LEN, fp);
		if (nitems != PKT_LEN)
			return 0;
		(*cb)(cb_args, (usb_pkt_rx *)buf, bank);
		bank = (bank + 1) % NUM_BANKS;
	}
}

static void unpack_symbols(uint8_t* buf, char* unpacked)
{
	int i, j;

	for (i = 0; i < SYM_LEN; i++) {
		/* output one byte for each received symbol (0x00 or 0x01) */
		for (j = 0; j < 8; j++) {
			unpacked[i * 8 + j] = (buf[i] & 0x80) >> 7;
			buf[i] <<= 1;
		}
	}
}

#define NUM_CHANNELS 79
#define RSSI_HISTORY_LEN NUM_BANKS
#define RSSI_BASE (-54)       /* CC2400 constant ... do not change */

/* Ignore packets with a SNR lower than this in order to reduce
 * processor load.  TODO: this should be a command line parameter. */

static char rssi_history[NUM_CHANNELS][RSSI_HISTORY_LEN] = {{INT8_MIN}};

/* Sniff for LAPs. If a piconet is provided, use the given LAP to
 * search for UAP.
 */
static void cb_rx(void* args, usb_pkt_rx *rx, int bank)
{
	btbb_packet *pkt = NULL;
	btbb_piconet *pn = (btbb_piconet *)args;
	char syms[BANK_LEN * NUM_BANKS];
	int i;
	char *channel_rssi_history;
	int8_t signal_level;
	int8_t noise_level;
	int8_t snr;
	int offset;
	uint32_t clkn;
	uint32_t lap;

	/* Sanity check */
	if (rx->channel > (NUM_CHANNELS-1))
		goto out;

	/* Copy packet (for dump) */
	memcpy(&packets[bank], rx, sizeof(usb_pkt_rx));

	unpack_symbols(rx->data, symbols[bank]);

	/* Do analysis based on oldest packet */
	rx = &packets[ (bank+1) % NUM_BANKS ];

	/* Shift rssi max history and append current max */
	channel_rssi_history = rssi_history[rx->channel];
	memmove(channel_rssi_history,
		channel_rssi_history+1,
		RSSI_HISTORY_LEN-1);
	channel_rssi_history[RSSI_HISTORY_LEN-1] = rx->rssi_max;

	/* Signal starts in oldest bank, but may cross into second
	 * oldest bank.  Take the max or the 2 maxs. */
/*
	signal_level = MAX(channel_rssi_history[0],
			   channel_rssi_history[1]) + RSSI_BASE;
*/

	/* Alternatively, use all banks in history. */
	signal_level = channel_rssi_history[0];
	for (i = 1; i < RSSI_HISTORY_LEN; i++)
		signal_level = MAX(signal_level, channel_rssi_history[i]);
	signal_level += RSSI_BASE;

	/* Noise is an IIR of averages */
	noise_level = rx->rssi_avg + RSSI_BASE;
	snr = signal_level - noise_level;

	/* WC4: use vm circbuf if target allows. This gets rid of this
	 * wrapped copy step. */

	/* Copy 2 oldest banks of symbols for analysis. Packet may
	 * cross a bank boundary. */
	for (i = 0; i < 2; i++)
		memcpy(syms + i * BANK_LEN,
		       symbols[(i + 1 + bank) % NUM_BANKS],
		       BANK_LEN);
	
	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */
	if (pn && btbb_piconet_get_flag(pn, BTBB_LAP_VALID))
		lap = btbb_piconet_get_lap(pn);
	else
		lap = LAP_ANY;

	/* Pass packet-pointer-pointer so that
	 * packet can be created in libbtbb. */
	offset = btbb_find_ac(syms, BANK_LEN, lap, max_ac_errors, &pkt);
	if (offset < 0)
		goto out;

	/* Copy out remaining banks of symbols for full analysis. */
	for (i = 1; i < NUM_BANKS; i++)
		memcpy(syms + i * BANK_LEN,
		       symbols[(i + 1 + bank) % NUM_BANKS],
		       BANK_LEN);

	/* Once offset is known for a valid packet, copy in symbols
	 * and other rx data. CLKN here is the 312.5us CLK27-0. The
	 * btbb library can shift it be CLK1 if needed. */
	clkn = (rx->clkn_high << 20) + (le32toh(rx->clk100ns) + offset + 1562) / 3125;
	btbb_packet_set_data(pkt, syms + offset, NUM_BANKS * BANK_LEN - offset,
			   rx->channel, clkn);

	/* When reading from file, caller will read
	 * systime before calling this routine, so do
	 * not overwrite. Otherwise, get current time. */
	if ( infile == NULL )
		systime = time(NULL);

	/* If dumpfile is specified, write out all banks to the
	 * file. There could be duplicate data in the dump if more
	 * than one LAP is found within the span of NUM_BANKS. */
	if (dumpfile) {
		for(i = 0; i < NUM_BANKS; i++) {
			uint32_t systime_be = htobe32(systime);
			if (fwrite(&systime_be, 
				   sizeof(systime_be), 1,
				   dumpfile)
			    != 1) {;}
			if (fwrite(&packets[(i + 1 + bank) % NUM_BANKS],
				   sizeof(usb_pkt_rx), 1, dumpfile)
			    != 1) {;}
		}
	}

	printf("systime=%u ch=%2d LAP=%06x err=%u clk100ns=%u clk1=%u s=%d n=%d snr=%d\n",
	       (int)systime,
	       btbb_packet_get_channel(pkt),
	       btbb_packet_get_lap(pkt),
	       btbb_packet_get_ac_errors(pkt),
	       rx->clk100ns,
	       btbb_packet_get_clkn(pkt),
	       signal_level,
	       noise_level,
	       snr);

	i = btbb_process_packet(pkt, pn);
	if(i < 0) {
		follow_pn = pn;
		stop_ubertooth = 1;
	}

out:
	if (pkt)
		btbb_packet_unref(pkt);
}

/* Receive and process packets. For now, returning from
 * stream_rx_usb() means that UAP and clocks have been found, and that
 * hopping should be started. A more flexible framework would be
 * nice. */
void rx_live(struct libusb_device_handle* devh, btbb_piconet* pn, int timeout)
{
	int r = btbb_init(max_ac_errors);
	if (r < 0)
		return;

	if (timeout)
		set_timeout(timeout);

	if (follow_pn)
		cmd_set_clock(devh, 0);
	else {
		stream_rx_usb(devh, XFER_LEN, 0, cb_rx, pn);
		/* Allow pending transfers to finish */
		sleep(1);
	}

	/* Used when follow_pn is preset OR set by stream_rx_usb above
	 * i.e. This cannot be rolled in to the above if...else
	 */
	if (follow_pn) {
		cmd_start_hopping(devh, btbb_piconet_get_clk_offset(follow_pn));
		stream_rx_usb(devh, XFER_LEN, 0, cb_rx, follow_pn);
	}
}

/* sniff one target LAP until the UAP is determined */
void rx_file(FILE* fp, btbb_piconet* pn)
{
	int r = btbb_init(max_ac_errors);
	if (r < 0)
		return;
	stream_rx_file(fp, 0, cb_rx, pn);
}

#ifdef USE_PCAP
/* Dump packet to PCAP file */
//static void log_packet(usb_pkt_rx *rx) {
//	le_packet_t p;
//	decode_le(rx->data, rx->channel + 2402, rx->clk100ns, &p);
//
//	unsigned packet_length = 4 + 2 + p.length + 3;
//
//	unsigned ppi_length = sizeof(ppi_fieldheader_t) + sizeof(ppi_btle_t);
//	printf("size %u\n", ppi_length);
//
//	void *logblob = malloc(sizeof(ppi_packet_header_t) + ppi_length + packet_length);
//	ppi_packet_header_t *ppih = (ppi_packet_header_t *)logblob;
//	ppih->pph_version = 0;
//	ppih->pph_flags = 0;
//	ppih->pph_len = htole16(sizeof(ppi_packet_header_t) + ppi_length);
//	ppih->pph_dlt = htole32(DLT_USER0); //htole32(DLT_BTLE);
//
//	// add PPI field
//	ppi_fieldheader_t *ppifh = logblob + sizeof(ppi_packet_header_t);
//	ppifh->pfh_type = htole16(PPI_BTLE);
//	ppifh->pfh_datalen = htole16(sizeof(ppi_btle_t));
//
//	ppi_btle_t *ppib = (void *)ppifh + sizeof(ppi_fieldheader_t);
//	ppib->btle_version = 0;
//	ppib->btle_channel = htole16(rx->channel + 2402);
//	ppib->btle_clkn_high = rx->clkn_high;
//	ppib->btle_clk100ns = htole32(rx->clk100ns);
//	ppib->rssi_max = rx->rssi_max;
//	ppib->rssi_min = rx->rssi_min;
//	ppib->rssi_avg = rx->rssi_avg;
//	ppib->rssi_count = rx->rssi_count;
//
//	void *packet_data_out = (void *)ppib + sizeof(ppi_btle_t);
//
//	// copy the data
//	memcpy(packet_data_out, rx->data, packet_length);
//
//	struct pcap_pkthdr wh;
//	struct timeval ts;
//	gettimeofday(&ts, NULL);
//
//	wh.ts = ts;
//	wh.caplen = wh.len = packet_length + sizeof(ppi_packet_header_t) + ppi_length;
//
//	pcap_dump((unsigned char *)dumper, &wh, logblob);
//	pcap_dump_flush(dumper);
//
//	/* FIXME: don't force a flush
//	 * Instead, write a signal handler to flush and close */
//
//	free(logblob);
//}
#endif // USE_PCAP

/*
 * Sniff Bluetooth Low Energy packets.  So far this is just a proof of concept
 * that only captures advertising packets.
 */
//void cb_btle(void* args, usb_pkt_rx *rx, int bank)
//{
//	int i;
//	u32 access_address = 0;
//
//	static u32 prev_ts = 0;
//
//	UNUSED(args);
//	UNUSED(bank);
//
//	/* Sanity check */
//	if (rx->channel > (NUM_CHANNELS-1))
//		return;
//
//	if (infile == NULL)
//		systime = time(NULL);
//
//	/* Dump to sumpfile if specified */
//	if (dumpfile) {
//		uint32_t systime_be = htobe32(systime);
//		if (fwrite(&systime_be, sizeof(systime_be), 1, dumpfile) != 1) {;}
//		if (fwrite(rx, sizeof(usb_pkt_rx), 1, dumpfile) != 1) {;}
//	}
//
//#ifdef USE_PCAP
//	/* Dump to PCAP if specified */
//	if (pcap_dumpfile) {
//		log_packet(rx);
//	}
//#endif // USE_PCAP
//
//	for (i = 0; i < 4; ++i)
//		access_address |= rx->data[i] << (i * 8);
//
//	u32 ts_diff = rx->clk100ns - prev_ts;
//	prev_ts = rx->clk100ns;
//	printf("systime=%u freq=%d addr=%08x delta_t=%.03f ms\n",
//		   systime, rx->channel + 2402, access_address, ts_diff / 10000.0);
//
//	int len = (rx->data[5] & 0x3f) + 6 + 3;
//	if (len > 50) len = 50;
//
//	for (i = 4; i < len; ++i)
//		printf("%02x ", rx->data[i]);
//	printf("\n");
//
//	le_packet_t p;
//	decode_le(rx->data, rx->channel + 2402, rx->clk100ns, &p);
//	le_print(&p);
//	printf("\n");
//
//	fflush(stdout);
//}

void rx_btle_file(FILE* fp)
{
	stream_rx_file(fp, 0, cb_btle, NULL);
}

static void cb_dump_bitstream(void* args, usb_pkt_rx *rx, int bank)
{
	int i;
	char nl = '\n';

	UNUSED(args);

	unpack_symbols(rx->data, symbols[bank]);

	// convert to ascii
	for (i = 0; i < BANK_LEN; ++i)
		symbols[bank][i] += 0x30;

	fprintf(stderr, "rx block timestamp %u * 100 nanoseconds\n", rx->clk100ns);
	if (dumpfile == NULL) {
		if (fwrite(symbols[bank], sizeof(u8), BANK_LEN, stdout) != 1) {;}
		fwrite(&nl, sizeof(u8), 1, stdout);
    } else {
		if (fwrite(symbols[bank], sizeof(u8), BANK_LEN, dumpfile) != 1) {;}
		fwrite(&nl, sizeof(u8), 1, dumpfile);
	}
}

static void cb_dump_full(void* args, usb_pkt_rx *rx, int bank)
{
	uint8_t *buf = (uint8_t*)rx;

	UNUSED(args);
	UNUSED(bank);

	fprintf(stderr, "rx block timestamp %u * 100 nanoseconds\n", rx->clk100ns);
	uint32_t time_be = htobe32((uint32_t)time(NULL));
	if (dumpfile == NULL) {
		if (fwrite(&time_be, 1, sizeof(time_be), stdout) != 1) {;}
		if (fwrite(buf, sizeof(u8), PKT_LEN, stdout) != 1) {;}
	} else {
		if (fwrite(&time_be, 1, sizeof(time_be), dumpfile) != 1) {;}
		if (fwrite(buf, sizeof(u8), PKT_LEN, dumpfile) != 1) {;}
	}
}

/* dump received symbols to stdout */
void rx_dump(struct libusb_device_handle* devh, int bitstream)
{
	if (bitstream)
		stream_rx_usb(devh, XFER_LEN, 0, cb_dump_bitstream, NULL);
	else
		stream_rx_usb(devh, XFER_LEN, 0, cb_dump_full, NULL);
}

int specan(struct libusb_device_handle* devh, int xfer_size, u16 num_blocks,
		u16 low_freq, u16 high_freq)
{
	return do_specan(devh, xfer_size, num_blocks, low_freq, high_freq, false);
}

int do_specan(struct libusb_device_handle* devh, int xfer_size, u16 num_blocks,
		u16 low_freq, u16 high_freq, char gnuplot)
{
	u8 buffer[BUFFER_SIZE];
	int r;
	int i, j;
	int xfer_blocks;
	int num_xfers;
	int transferred;
	int frequency;
	u32 time; /* in 100 nanosecond units */

	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	if(!Quiet)
		fprintf(stderr, "rx %d blocks of 64 bytes in %d byte transfers\n",
				num_blocks, xfer_size);

	cmd_specan(devh, low_freq, high_freq);

	while (num_xfers--) 
	{
		r = libusb_bulk_transfer(devh, DATA_IN, buffer, xfer_size,
				&transferred, TIMEOUT);
		if (r < 0) {
			fprintf(stderr, "bulk read returned: %d , failed to read\n", r);
			return -1;
		}
		if (transferred != xfer_size) {
			fprintf(stderr, "bad data read size (%d)\n", transferred);
			return -1;
		}
		if(!Quiet)
			fprintf(stderr, "transferred %d bytes\n", transferred);

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{
			time = buffer[4 + PKT_LEN * i]
					| (buffer[5 + PKT_LEN * i] << 8)
					| (buffer[6 + PKT_LEN * i] << 16)
					| (buffer[7 + PKT_LEN * i] << 24);
			if(!Quiet)
				fprintf(stderr, "rx block timestamp %u * 100 nanoseconds\n", time);
			for (j = PKT_LEN * i + SYM_OFFSET; j < PKT_LEN * i + 62; j += 3) 
			{
				frequency = (buffer[j] << 8) | buffer[j + 1];
				if (buffer[j + 2] > 150) { /* FIXME  */
					if(gnuplot == GNUPLOT_NORMAL)
						printf("%d %d\n", frequency, buffer[j + 2]);
					else if(gnuplot == GNUPLOT_3D)
						printf("%f %d %d\n", ((double)time)/10000000, frequency, buffer[j + 2]);
					else
//						printf("%f, %d, %d\n", ((double)time)/10000000, frequency, buffer[j + 2]);
						printf("%f, %d, %d\n", ((double)time)/10000000, frequency, -54 + (int8_t) buffer[j + 2]);
				}
				if (frequency == high_freq && !gnuplot)
					printf("\n");
			}
		}
		fflush(stderr);
	}
	return 0;
}

void ubertooth_stop(struct libusb_device_handle *devh)
{
	/* FIXME make sure xfers are not active */
	libusb_free_transfer(rx_xfer);
	if (devh != NULL)
		libusb_release_interface(devh, 0);
	libusb_close(devh);
	libusb_exit(NULL);
}

struct libusb_device_handle* ubertooth_start(int ubertooth_device)
{
	int r;
	struct libusb_device_handle *devh = NULL;

	r = libusb_init(NULL);
	if (r < 0) {
		fprintf(stderr, "libusb_init failed (got 1.0?)\n");
		return NULL;
	}

	devh = find_ubertooth_device(ubertooth_device);
	if (devh == NULL) {
		fprintf(stderr, "could not open Ubertooth device\n");
		ubertooth_stop(devh);
		return NULL;
	}

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		fprintf(stderr, "usb_claim_interface error %d\n", r);
		ubertooth_stop(devh);
		return NULL;
	}

	return devh;
}
////////////////////////////////////////////////////////////////////
static uint64_t air_to_host64(char *air_order, int bits)
{
	int i;
	uint64_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint64_t)air_order[i] << i);
	return host_order;
}
////////////////////////////////////////////////////////////////////
static uint32_t air_to_host32(char *air_order, int bits)
{
	int i;
	uint32_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint32_t)air_order[i] << i);
	return host_order;
}
static uint16_t air_to_host16(char *air_order, int bits)
{
	int i;
	uint16_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint16_t)air_order[i] << i);
	return host_order;
}
static uint8_t air_to_host8(char *air_order, int bits)
{
	int i;
	uint8_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint8_t)air_order[i] << i);
	return host_order;
}
/* count the number of 1 bits in a uint64_t */
static int count_bits(uint64_t n)
{
	uint8_t i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
}
//////////////////////////////
/* encode 10 bits with 2/3 rate FEC code, a (15,10) shortened Hamming code */
static uint16_t fec23(uint16_t data)
{
	int i;
	uint16_t codeword = 0;

	/* host order, not air order */
	for (i = 0; i < 10; i++)
		if (data & (1 << i))
			codeword ^= fec23_gen_matrix[i];

	return codeword;
}
///////////////////////////////////////////////////////////////////
/* Decode 2/3 rate FEC, a (15,10) shortened Hamming code */
//static char *unfec23(char *input, int length)
static int unfec23_local(char *output, char *input, int length)
{
	/* input points to the input data
	 * length is length in bits of the data
	 * before it was encoded with fec2/3 */
	int iptr, optr, count;
//	char* output;
	uint8_t diff, check;
	uint16_t data, codeword;

	diff = length % 10;
	// padding at end of data
	if(0!=diff)
		length += (10 - diff);

//	output = (char *) malloc(length);

	for (iptr = 0, optr = 0; optr<length; iptr += 15, optr += 10) 
	{
		// copy data to output
		for(count=0;count<10;count++)
			output[optr+count] = input[iptr+count];

		// grab data and error check in host format
		data = air_to_host16(input+iptr, 10);
		check = air_to_host8(input+iptr+10, 5);

		// call fec23 on data to generate the codeword
		codeword = fec23(data);
		diff = check ^ (codeword >> 10);

		/* no errors or single bit errors (errors in the parity bit):
		 * (a strong hint it's a real packet)
		 * Otherwise we need to corret the output*/
		if (diff & (diff - 1)) {
			switch (diff) {
			/* comments are the bit that's wrong and the value
			* of diff in air order, from the BT spec */
				// 1000000000 11010
				case 0x0b: output[optr] ^= 1; break;
				// 0100000000 01101
				case 0x16: output[optr+1] ^= 1; break;
				// 0010000000 11100
				case 0x07: output[optr+2] ^= 1; break;
				// 0001000000 01110
				case 0x0e: output[optr+3] ^= 1; break;
				// 0000100000 00111
				case 0x1c: output[optr+4] ^= 1; break;
				// 0000010000 11001
				case 0x13: output[optr+5] ^= 1; break;
				// 0000001000 10110
				case 0x0d: output[optr+6] ^= 1; break;
				// 0000000100 01011
				case 0x1a: output[optr+7] ^= 1; break;
				// 0000000010 11111
				case 0x1f: output[optr+8] ^= 1; break;
				// 0000000001 10101
				case 0x15: output[optr+9] ^= 1; break;
				/* not one of these errors, probably multiple bit errors
				* or maybe not a real packet, safe to drop it? */
				default: 
				//	free(output); 
					return 0;
			}
		}
	}
//	return output;
	return 0;
}

////////////////////////////////////////////////////////////////////
int cmd_set_bdaddr1(struct libusb_device_handle* devh, u32 address)
{
	int r, data_len;
//	u64 syncword;
	data_len = 4;
	unsigned char data[data_len];

//	syncword = btbb_gen_syncword(address & 0xffffff);
	//printf("syncword=%#llx\n", syncword);
	for(r=0; r < 4; r++)
		data[r] = (address >> (8*r)) & 0xff;

	r = libusb_control_transfer(devh, CTRL_OUT, UBERTOOTH_SET_BDADDR, 0, 0,
		data, data_len, 1000);
	if (r < 0) {
		if (r == LIBUSB_ERROR_PIPE) {
			fprintf(stderr, "control message unsupported\n");
		} else {
			show_libusb_error(r);
		}
		return r;
	} else if (r < data_len) {
		fprintf(stderr, "Only %d of %d bytes transferred\n", r, data_len);
		return 1;
	}
	return 0;
}
///////////////////////////////////////////////////////////////////
uint32_t reverse32(uint32_t x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
    return x;
}
//////////////////////////////////////////////////
/// max 4 bytes ==> the output = 4 * 8 = 32 bits
void unpack_symbols33(uint8_t* buf, uint8_t * unpacked)
{
	int i, j, k = 0;
// 4* 3 because we have fec13 so 4 bytes will be 12 bytes
//	for (i = 0; i < SYM_LEN; i++) {
//	for (i = 0; i < (4*3); i++) {
	for (i = 0; i < (3*3); i++) {
		/* output one byte for each received symbol (0x00 or 0x01) */
		for (j = 7; j > -1; j--) {
//			unpacked[i * 8 + j] = (buf[i] & 0x80) >> 7;
			unpacked[ k ] = 0x01 & (buf[i]  >> j );
			++ k ;
//			buf[i] <<= 1;
		}
	}
}
//////////////////////////////////////////////////
void unpack_symbols42(uint8_t* buf, uint8_t * unpacked, const int bytes)
{
	int i, j, k = 0;
// 4* 3 because we have fec13 so 4 bytes will be 12 bytes
//	for (i = 0; i < SYM_LEN; i++) {
//	for (i = 0; i < (4*3); i++) {
	for (i = 0; i < bytes; i++) {//20 bytes
		/* output one byte for each received symbol (0x00 or 0x01) */
		for (j = 7; j > -1; j--) {
//			unpacked[i * 8 + j] = (buf[i] & 0x80) >> 7;
			unpacked[ k ] = 0x01 & (buf[i]  >> j );
			++ k ;
//			buf[i] <<= 1;
		}
	}
}
//////////////////////////////////////////////////

void init_pico_info ( struct _piconet_info_ *p_info )

{
	int shift;
	uint32_t sync1, sync2;
	uint64_t sync3, sync4, local_reversed;

	p_info->LAP		= p_info->address & 0xffffff;
	p_info->UAP 		= (p_info->address >> 24) & 0xff;
	p_info->syncword  	= btbb_gen_syncword (  p_info->LAP );

	sync1 		= 0xffffffff & p_info->syncword;
	sync2 		= 0xffffffff & (p_info->syncword >> 32);

	sync3 		= 0xffffffff & ( reverse32 ( sync1 )  );
	sync3 		= sync3 << 32;

	sync4		= 0xffffffff & ( reverse32 ( sync2 )  );

	p_info->reversed_syncword 	= sync3 | sync4 ;

//	if ( 1 == (0x01 & (p_info->reversed_syncword >> 63) ) )
//
//		p_info->preamble_reversed_syncword = 0xA000000000000000 | (p_info->reversed_syncword >> 4);
//	else 
//		p_info->preamble_reversed_syncword = 0x5000000000000000 | (p_info->reversed_syncword >> 4);

	for ( shift = 0; shift < 8; shift ++ )
	{
		p_info->air_order_syncword [ shift ] = 0x00ffffffffffffff & (p_info->reversed_syncword >> shift);

		local_reversed = 0x00ffffffffffffff & (p_info->reversed_syncword >> shift);
		p_info->reversed1 [ shift ] = 0;

		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x00000000000000ff & (local_reversed >> 56) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x000000000000ff00 & (local_reversed >> 40) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x0000000000ff0000 & (local_reversed >> 24) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x00000000ff000000 & (local_reversed >> 8)  );

		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0xff00000000000000 & (local_reversed << 56) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x00ff000000000000 & (local_reversed << 40) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x0000ff0000000000 & (local_reversed << 24) );
		p_info->reversed1 [ shift ] 	= p_info->reversed1 [ shift ] | (0x000000ff00000000 & (local_reversed << 8)  );
	}

}
///////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
uint8_t uber_ctrl_sig (struct ShMemory  *ShmPTR, uint8_t hopping_mode)
{

//	assert ( ShmPTR );

//	uint8_t ch  [ CHK_SIZE ];//ch0, ch1, ch2, ch3; 
	uint8_t ptyp[ CHK_SIZE ];//ptyp0, ptyp1, ptyp2, ptyp3;
	uint8_t clk [ CHK_SIZE ];//clk0, clk1, clk2, clk3;  
	int ofst625 [ CHK_SIZE ];//, ofst6251, ofst6252, ofst6253;
	int i, pkt_idx ;

	if ( BASIC_HPNG == hopping_mode )
	{

		pkt_idx 	= ShmPTR->basic_pkt_idx ;

		for ( i = 0 ; i < CHK_SIZE; i ++)
		{
//			ptyp [ i ]		= ShmPTR->basic_pkt_type 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
			clk  [ i ]		= ShmPTR->basic_pkt_clk6_1 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
			ofst625 [ i ]		= ShmPTR->basic_pkt_625offset 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
		}


	}

	else if ( ADPTV_HPNG == hopping_mode )

	{
		pkt_idx 	= ShmPTR->adptv_pkt_idx  ;

		for ( i = 0 ; i < CHK_SIZE; i ++)
		{
//			ptyp [ i ]		= ShmPTR->adptv_pkt_type 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
			clk  [ i ]		= ShmPTR->adptv_pkt_clk6_1 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
			ofst625 [ i ]		= ShmPTR->adptv_pkt_625offset 	[ (pkt_idx - CHK_SIZE + i) % PKT_BUF_SIZE];
		}

	}



//	int n_pkt = (ShmPTR->n_pkt_buf - 5) % PKT_BUF;
//	int INDX = BUF_INDEX ;
/////// case 1
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 430 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 500)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1060 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1180)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (STANDARD_SPEED);
	}

/////// case 2
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 500 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 580)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1130 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1250)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (SLOW_DOWN22);
	}


/////// case 3
//	if ( 	
////		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
//		( 900 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 1100)  	&&
//		( 01 == (clk [ 0 ] % 2 ) )
//
//	)
//	{
//	if ( 	
//		( 900 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 1100)  	&&
//		( 01 == (clk [ 0 ] % 2 ) )
//	)
//		return (SLOW_DOWN22);
//	}


/////// case 4
//	if ( 	
////		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
//		( 550 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 730)  	&&
//		( 00 == (clk [ 0 ] % 2 ) )
//
//	)
//	{
//	if ( 	
//		( 1180 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1280)  	&&
//		( 01 == (clk [ 1 ] % 2 ) )
//	)
//		return (SLOW_DOWN22);
//	}
//
/////// case 5
//	if ( 	
////		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
//		( 1150 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 1290)  	&&
//		( 00 == (clk [ 0 ] % 2 ) )
//
//	)
//	{
//	if ( 	
//		( 550 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 800)  	&&
//		( 01 == (clk [ 1 ] % 2 ) )
//	)
//		return (SLOW_DOWN22);
//	}
//

/////// case 1

/*	if ( 
		(00 == ShmPTR->pkt_type [INDX][n_pkt] || 01 == ShmPTR->pkt_type [INDX][n_pkt] ) 
		&& ( 400 < ShmPTR->pkt_off625 [INDX][n_pkt] && ShmPTR->pkt_off625 [INDX][n_pkt] < 500)

	 )

	{
		ch = ShmPTR->pkt_ch [INDX][n_pkt];

		if ( 
			(14 == ShmPTR->pkt_type [INDX][n_pkt+1] || 15 == ShmPTR->pkt_type [INDX][n_pkt+1] || 04 == ShmPTR->pkt_type [INDX][n_pkt+1]) 
			&& ( 1000 < ShmPTR->pkt_off625 [INDX][n_pkt+1] &&  ShmPTR->pkt_off625 [INDX][n_pkt+1] < 1150 )
			&& ( ch == ShmPTR->pkt_ch [INDX][n_pkt+1] )

		 )

		{
//			ch = ShmPTR->pkt_ch [n_pkt+1];

//			if ( 
//			(00 == ShmPTR->pkt_type [n_pkt+2] || 01 == ShmPTR->pkt_type [n_pkt+2] ) 
//			&& ( 400 < ShmPTR->pkt_off625 [n_pkt+2] && 500 > ShmPTR->pkt_off625 [n_pkt+2])
//			&& ( ch == ShmPTR->pkt_ch [n_pkt+2] )
//			 )

			{

				return (STANDARD_SPEED);

			}


		}

	}

/////// case 2
	if ( 
		(00 == ShmPTR->pkt_type [INDX][n_pkt] || 01 == ShmPTR->pkt_type [INDX][n_pkt] ) 
		&& ( 500 < ShmPTR->pkt_off625 [INDX][n_pkt] && ShmPTR->pkt_off625 [INDX][n_pkt] < 600)

	 )

	{
		ch = ShmPTR->pkt_ch [INDX][n_pkt];

		if ( 
			(14 == ShmPTR->pkt_type [INDX][n_pkt+1] || 15 == ShmPTR->pkt_type [INDX][n_pkt+1] || 04 == ShmPTR->pkt_type [INDX][n_pkt+1]) 
			&& ( 1100 < ShmPTR->pkt_off625 [INDX][n_pkt+1] &&  ShmPTR->pkt_off625 [INDX][n_pkt+1] < 1120 )
			&& ( ch == ShmPTR->pkt_ch [INDX][n_pkt+1] )

		 )

		{
//			ch = ShmPTR->pkt_ch [n_pkt+1];

//			if ( 
//			(00 == ShmPTR->pkt_type [n_pkt+2] || 01 == ShmPTR->pkt_type [n_pkt+2] ) 
//			&& ( 400 < ShmPTR->pkt_off625 [n_pkt+2] && 500 > ShmPTR->pkt_off625 [n_pkt+2])
//			&& ( ch == ShmPTR->pkt_ch [n_pkt+2] )
//			 )

			{

				return (SLOW_DOWN2);

			}


		}

	}


////////////// case 3

	if ( 
		(00 == ShmPTR->pkt_type [INDX][n_pkt] || 01 == ShmPTR->pkt_type [INDX][n_pkt] ) 
		&& ( 700 < ShmPTR->pkt_off625 [INDX][n_pkt] && ShmPTR->pkt_off625 [INDX][n_pkt] < 1100)

	 )

	{
		ch = ShmPTR->pkt_ch [INDX][n_pkt];

		if ( 
			(14 == ShmPTR->pkt_type [INDX][n_pkt+1] || 15 == ShmPTR->pkt_type [INDX][n_pkt+1] || 04 == ShmPTR->pkt_type [INDX][n_pkt+1]) 
			&& ( 250 < ShmPTR->pkt_off625 [INDX][n_pkt+1] &&  ShmPTR->pkt_off625 [INDX][n_pkt+1] < 600 )
//			&& ( ch == ShmPTR->pkt_ch [n_pkt+1] )

		 )

		{
//			ch = ShmPTR->pkt_ch [n_pkt+1];

//			if ( 
//			(00 == ShmPTR->pkt_type [n_pkt+2] || 01 == ShmPTR->pkt_type [n_pkt+2] ) 
//			&& ( 400 < ShmPTR->pkt_off625 [n_pkt+2] && 500 > ShmPTR->pkt_off625 [n_pkt+2])
//			&& ( ch == ShmPTR->pkt_ch [n_pkt+2] )
//			 )

			{

				return (SLOW_DOWN23);
//				return (SLOW_DOWN22);
//				return (SPEED_UP11);
//				return (SLOW_AND_STANDARD24);

			}


		}

	}

////////////// case 4

	if ( 
		( 14 == ShmPTR->pkt_type [INDX][n_pkt] || 15 == ShmPTR->pkt_type [INDX][n_pkt] || 04 == ShmPTR->pkt_type [INDX][n_pkt]) 
		&& ( 400 < ShmPTR->pkt_off625 [INDX][n_pkt] && ShmPTR->pkt_off625 [INDX][n_pkt] < 500)

	 )

	{

		if ( 
			(14 == ShmPTR->pkt_type [INDX][n_pkt+1] || 15 == ShmPTR->pkt_type [INDX][n_pkt+1] || 04 == ShmPTR->pkt_type [INDX][n_pkt+1]) 
			&& ( 400 < ShmPTR->pkt_off625 [INDX][n_pkt+1] &&  ShmPTR->pkt_off625 [INDX][n_pkt+1] < 500 )

		 )

		{


			if ( 
				(14 == ShmPTR->pkt_type [INDX][n_pkt+2] || 15 == ShmPTR->pkt_type [INDX][n_pkt+2] || 04 == ShmPTR->pkt_type [INDX][n_pkt+2]) 
				&& ( 400 < ShmPTR->pkt_off625 [INDX][n_pkt+2] &&  ShmPTR->pkt_off625 [INDX][n_pkt+2] < 500 )

			 )



			{

//				return (SPEED_UP11);

			}


		}

	}

*/

	return 0;
}
//////////////////////////////////////////////////////////
//uint8_t uber_ctrl_sig2 (struct ShMemory  *ShmPTR, uint8_t hopping_mode)
uint8_t uber_ctrl_sig2 ( struct buf_info * buf_info)
{

	uint8_t ptyp[ CHK_SIZE ];
	uint8_t clk [ CHK_SIZE ];
	int ofst625 [ CHK_SIZE ];
	int i, pkt_idx ;

	pkt_idx 	= buf_info->local_buf_idx ;

	for ( i = 0 ; i < CHK_SIZE; i ++)
	{
		clk  [ i ]		= buf_info->clk6 	[ (pkt_idx - CHK_SIZE + i) % LOCAL_BUF_SIZE];
		ofst625 [ i ]		= buf_info->ofst625 	[ (pkt_idx - CHK_SIZE + i) % LOCAL_BUF_SIZE];
	}


/////// case 1
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 430 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 500)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1060 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1180)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (STANDARD_SPEED);
	}

/////// case 2
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 500 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 580)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1130 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1250)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (SLOW_DOWN22);
	}



	return 0;
}
//////////////////////////////////////////////////////////////
uint8_t uber_ctrl_sig4 ( const struct ShMemory2 * ShmPTR2)
{

int loc_idx = ( ShmPTR2->ch_idx - 4 ) % SHM2_PKT_BUF_SIZE;
/////// case 1
int ofst625_1 = ShmPTR2->ofst625_1 [ loc_idx ];
int ofst625_2 = ShmPTR2->ofst625_2 [ loc_idx ];
///////////////////////////////////////////////////////////////////
	if (

	( 4900 < ofst625_1  &&  ofst625_1 < 5700 )

	)

	{
		if ( 
			( 11000 < ofst625_2  &&  ofst625_2  < 11500) 
		)
			return (STANDARD_SPEED);		

	}


	if (

	( 5700 < ofst625_1   &&  ofst625_1 < 6000 )

	)

	{
		if ( 
			( 11500 < ofst625_2  &&  ofst625_2  < 12500) 
		)
			return (SLOW_DOWN22);

	}
//////////////////////////////////////////////////////////////////////////
	if (

	( 20 < ofst625_1  ) && ( ofst625_1 < 350 )

	)

	{
		if ( 
			( 7000 < ofst625_2  && ofst625_2  < 7700) 
		)
			return (STANDARD_SPEED);		

	}


	if (

	( 350 < ofst625_1  && ofst625_1 < 750 )

	)

	{
		if ( 
			( 7000 < ofst625_2  &&  ofst625_2  < 8800) 
		)
			return (SLOW_DOWN22);

	}


	return 0;
}
///////////////////////////////////////////////////////////
uint8_t uber_ctrl_sig5 ( const struct _slt_buf *slt)
{

/////// case 1
int ofst625_1 = slt->ofst625_1 ;
int ofst625_2 = slt->ofst625_2 ;
///////////////////////////////////////////////////////////////////
	if (	( 4900 < ofst625_1)  &&  (ofst625_1 < 5700 )	)
	{
		if ( ( 11000 < ofst625_2)  &&  (ofst625_2  < 12000) )
			return (STANDARD_SPEED);		
	}


	if (	( 5700 < ofst625_1)   &&  (ofst625_1 < 6000 )	)
	{
		if ( ( 11500 < ofst625_2  &&  ofst625_2  < 12500) )
			return (SLOW_DOWN22);
	}
//////////////////////////////////////////////////////////////////////////
	if ( ( 20 < ofst625_1  ) && ( ofst625_1 < 450 )	)
	{
		if ( ( 7000 < ofst625_2)  && (ofst625_2  < 7900) 	)
			return (STANDARD_SPEED);		
	}


	if ( ( 350 < ofst625_1)  && (ofst625_1 < 750 )	)
	{
		if ( ( 7000 < ofst625_2  &&  ofst625_2  < 8800) )
			return (SLOW_DOWN22);
	}

	return 0;
}

////////////////////////////////////////////////////////
//uint8_t uber_ctrl_sig3 ( struct _ctrl_speed_data * speed_ctrl)
//{
//
//
///////// case 1
//	if ( ( 4900 < speed_ctrl->avg_ofst625_1) &&  (speed_ctrl->avg_ofst625_1  < 5700 )  )
//	{
//		if ( ( 11000 < speed_ctrl->avg_ofst625_2) &&  (speed_ctrl->avg_ofst625_2  < 12000) )
//			return (STANDARD_SPEED);
//	}
//
///////// case 2
//	if ( ( 5700 < speed_ctrl->avg_ofst625_1) &&  (speed_ctrl->avg_ofst625_1  < 6000 )  )
//	{
//		if ( ( 12000 < speed_ctrl->avg_ofst625_2) &&  (speed_ctrl->avg_ofst625_2  < 12500) )
//			return (SLOW_DOWN22);
//	}
//
//
////////////////////////////////////////////////////////////////////////////////////////////
///////// case 3
//	if ( ( 20 < speed_ctrl->avg_ofst625_1) &&  (speed_ctrl->avg_ofst625_1  < 350 )  )
//	{
//		if ( ( 7300 < speed_ctrl->avg_ofst625_2) &&  (speed_ctrl->avg_ofst625_2  < 7700) )
//			return (STANDARD_SPEED);
//	}
//
///////// case 3
//	if ( ( 350 < speed_ctrl->avg_ofst625_1) &&  (speed_ctrl->avg_ofst625_1  < 750 )  )
//	{
//		if ( ( 7400 < speed_ctrl->avg_ofst625_2) &&  (speed_ctrl->avg_ofst625_2  < 8800) )
//			return (SLOW_DOWN22);
//	}
//
////////////////////////////////////////////////////////////////////////////////////////
//
//	return 0;
//}
////////////////////////////////////////////////////////
uint8_t uber_ctrl_sig9 ( struct _speed_ctrl_buf * buf_info)
{

	uint8_t ptyp[ CHK_SIZE ];
	uint8_t clk [ CHK_SIZE ];
	int ofst625 [ CHK_SIZE ];
	int i, pkt_idx ;

	pkt_idx 	= buf_info->local_buf_idx ;

	for ( i = 0 ; i < CHK_SIZE; i ++)
	{
		clk  [ i ]		= buf_info->clk6 	[ (pkt_idx - CHK_SIZE + i) % LOCAL_BUF_SIZE];
		ofst625 [ i ]		= buf_info->ofst625 	[ (pkt_idx - CHK_SIZE + i) % LOCAL_BUF_SIZE];
	}


/////// case 1
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 430 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 500)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1060 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1180)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (STANDARD_SPEED);
	}

/////// case 2
	if ( 	
//		( 00 == ptyp [0] || 01 == ptyp [0] ) 		&& 
		( 500 < ofst625 [ 0 ] &&  ofst625[ 0 ] < 580)  	&&
		( 00 == (clk [ 0 ] % 2 ) )

	)
	{
	if ( 	
		( 1130 < ofst625 [ 1 ] &&  ofst625[ 1 ] < 1250)  	&&
		( 01 == (clk [ 1 ] % 2 ) )
	)
		return (SLOW_DOWN22);
	}



	return 0;
}
/////////////////////////////////////////////////////////////
static int find_known_lap4 ( struct buf_info *b_info, struct _piconet_info_ *p_info, char *stream, int search_length, int max_ac_errors )
{

	uint64_t  * p1 ;
	int count = -1 , bit_errors, shift;

//	printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ shift ]   );

	for (count = 0; count < 50; count++) 
	{

		p1 		= (uint64_t *) & stream [ count ];
		p1 [ 0 ] 	= 0xffffffffffffff00 & p1 [ 0 ];

		for ( shift = 0; shift < 8; shift++ )
		{
//			printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ shift ]   );
			bit_errors = count_bits ( p1 [ 0 ] ^ p_info->reversed1 [ shift ]   );
			if  ( bit_errors <= max_ac_errors )
			{	
				b_info->ac_offset_find3 = (count * 8) + shift;
				b_info->byte		= count;
				b_info->shift		= shift;
				b_info->err		= bit_errors;
				printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ 0 ]   );
				return 1;
			}
		}
	}

	return 0;
}
///////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
// stream of 50 * 8 = 400 bytes + 50 from prev_buf = 450
static int find_known_lap5 ( struct buf_info *b_info, struct _piconet_info_ *p_info, uint8_t *stream, int jump,  int max_ac_errors )
{

	uint64_t  * p1 ;
	int count = -1 , bit_errors, shift;

//	for (count = 0; count < 50; count++) 
	for (count = jump; count < 50; count++) 
	{

		p1 		= (uint64_t *) & stream [ count ];
		p1 [ 0 ] 	= 0xffffffffffffff00 & p1 [ 0 ];

		for ( shift = 0; shift < 8; shift++ )
		{
//			printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ shift ]   );
			bit_errors = count_bits ( p1 [ 0 ] ^ p_info->reversed1 [ shift ]   );
			if  ( bit_errors <= max_ac_errors )
			{	
				b_info->ac_offset_find3 = (count * 8) + shift;
				b_info->byte		= count;
				b_info->shift		= shift;
				return 1;
			}
		}
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////
/* extract UAP by reversing the HEC computation */
static int8_t UAP_from_hec(uint16_t data, uint8_t hec)
{
        int i;

        for (i = 9; i >= 0; i--) {
                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
                if (hec & 0x80)
                        hec ^= 0x65;

                hec = (hec << 1) | (((hec >> 7) ^ (data >> i)) & 0x01);
        }
//        return  reverse(hec);
	return (
	(hec & 0x80) >> 7 | 
	(hec & 0x40) >> 5 | 
	(hec & 0x20) >> 3 | 
	(hec & 0x10) >> 1 | 
	(hec & 0x08) << 1 | 
	(hec & 0x04) << 3 | 
	(hec & 0x02) << 5 | 
	(hec & 0x01) << 7 );
}
///////////////////////////////////////////////////////////////////////////////
/* Decode 1/3 rate FEC, three like symbols in a row */
int unfec13_local(uint8_t *input, uint8_t *output, int length)
{
	int a, b, c, i;
	int be = 0; /* bit errors */
	for (i = 0; i < length; i++) {
		a = 3 * i;
		b = a + 1;
		c = a + 2;
		output[i] = ((input[a] & input[b]) | (input[b] & input[c]) |
				(input[c] & input[a]));

		be += ((input[a] ^ input[b]) | (input[b] ^ input[c]) |
				(input[c] ^ input[a]));

	}

	return be;
}

/////////////////////////////////////////////////////////
//int round_slots(float x)
uint32_t round_slots(float x)
{
	// Threshold here is 0.1
//	if ( (int) (x) < (int) (x+0.1))
//	if ( (int) (x) < (int) (x+0.3))
	if ( (uint32_t) (x) < (uint32_t) (x+0.3))
//	if ( (int) (x) < (int) (x+0.5))
//		return (int) (x+1);
		return (uint32_t) (x+1);
	else 
//		return (int) x;
		return (uint32_t) x;
}
/////////////////////////////////////////////////
/* Remove the whitening from an air order array */
void unwhiten1(char* input, char* output, int clock, int length, int skipp)
{
	int count, index=0;
	index = INDICES[clock & 0x3f];
	index += skipp;
	index %= 127;

	for(count = 0; count < length; count++)
	{
		/* unwhiten if whitened, otherwise just copy input to output */
		output[count] = (1) ? input[count] ^ WHITENING_DATA[index] : input[count];
		index += 1;
		index %= 127;
	}
}
//////////////////////////////////////////////
//void unwhiten3(char* input, char* output, int clock, int length, int skipp)
void unwhiten3( uint8_t * output , int clock, int length, int skipp)
{
	int count, index;
	index = INDICES[clock & 0x3f];
	index += skipp;
	index %= 127;

	for(count = 0; count < length; count++)
	{
		/* unwhiten if whitened, otherwise just copy input to output */
//		output[count] = (1) ? input[count] ^ WHITENING_DATA[index] : input[count];
output[count] = WHITENING_DATA[index];
//		printf ("%u", output[count] = WHITENING_DATA[index] );

		index += 1;
		index %= 127;

	}
printf ("\n");
}

////////////////////////////////////////////////////////////////
static void cb_rx_BASIC4( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx->data, 50 );
	memcpy ( prev_pkt2.data  , rx->data, 50 );


	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = 0xffffffff & le32toh (rx->clk100ns2);

//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//////////////////////////////////
////			index = INDICES[clock & 0x3f];
//			index = INDICES[clock       ];
//			index += skipp;
//			index %= 127;
//
//			for(count = 0; count < length; count++)
//			{
//				/* unwhiten if whitened, otherwise just copy input to output */
//				unwhite_header3[count] = (1) ? white_header3[count] ^ WHITENING_DATA[index] : white_header3[count];
//				index += 1;
//				index %= 127;
//			}
////////////////////////////////


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x3ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );


		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",


//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			pkt_LT_ADD, 
//			b_info->channel,
//			pico_info->LAP,
//			pkt_time, 
//			round_slts,
//			slots  );
//


		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
			b_info->ac_offset_find3,
			0x3f & rx->status,
			clk_count,
			pkt_LT_ADD, 
			0x3ff & hdr_data2,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
			pkt_time, 
			b_info->pkt_clk100ns2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}
//////////////////////////////////////////////////////////
static void cb_rx_BASIC42( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header422 [ 1024 ], unfec23_output[1024], fec13_header42 [ 1024 ], unwhite_header42[ 1024 ],
		fec13_header3  [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx->data, 50 );
	memcpy ( prev_pkt2.data  , rx->data, 50 );


	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = 0xffffffff & le32toh (rx->clk100ns2);

	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
//		unpack_symbols42		( &rx_data [ b_info->byte + 8 ], fec13_header42 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);
		// fec13_header42 + b_info->shift + 4 + 54 of the hrd

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);

			hdr_data2 = air_to_host32 (unwhite_header3, 18);

			hec       = 0xff & (hdr_data2 >> 10);

			if (pico_info->UAP == (0xff & UAP_from_hec( (0x3ff & hdr_data2), (0xff & hec)) ) )
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );


		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{

//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			pkt_LT_ADD, 
//			b_info->channel,
//			pico_info->LAP,
//			pkt_time, 
//			round_slts,
//			slots  );
//


		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
			b_info->ac_offset_find3,
			0x3f & rx->status,
			clk_count,
			pkt_LT_ADD, 
			0x3ff & hdr_data2,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
			pkt_time, 
			b_info->pkt_clk100ns2,
			slots  );

//		if ( ( 1 == clk_count ) && (( 15 ==  b_info->ptype)||( 14 ==  b_info->ptype)) )
//		if ( ( 1 == clk_count ) && ( 15 ==  b_info->ptype) )
//		if ( ( 1 == clk_count ) && ( 1 ==  b_info->ptype) )
		if (  ( 1 == clk_count ) && ( 0 == ( b_info->clk6_1 % 2 ) ) )
		{


//		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
//		unpack_symbols42		( &rx_data [ b_info->byte + 8 ], fec13_header42 );
//		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);
//		// fec13_header42 + b_info->shift + 4 + 54 of the hrd
//
//		for (clock = 0; clock < 64; clock++)
//		{
//
//			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);


			unpack_symbols42	( &rx_data [ b_info->byte + 8 ], fec13_header42, 40 );
//			unpack_symbols42	( &rx_data [ b_info->byte + 8 ], fec13_header422, 40 );


			for ( i = 0; i < 54; i ++)
				printf ("%u", 
					fec13_header42 [b_info->shift + 4 +  i ]
				);

			printf ("\n");

//			if ( 10 ==  b_info->ptype )
			{
			unfec23_local ( unfec23_output, &fec13_header42 [ b_info->shift + 4 +54 ], 100);
			unwhiten1 		( unfec23_output , unwhite_header42, b_info->clk6_1, 100, 18);
			}

//			else 
//			unwhiten1 		(&fec13_header42 [ b_info->shift + 4 +54], unwhite_header42, b_info->clk6_1, 100, 18);
////			unwhiten1 		(&fec13_header42 [ b_info->shift + 4 +54], unwhite_header42, 63^b_info->clk6_1, 100, 18);


			printf ("\n");
//			unwhiten1 		( fec13_header42 + b_info->shift + 4 +54 , unwhite_header42, 63^b_info->clk6_1, 100, 18);

//
			printf ("\n");

			for ( i = 0; i < 80; i +=8)

				printf ("%02x", 
//				printf ("%c", 
//				"%" PRIx64 "\n",
////					unwhite_header42 [  i ]
			air_to_host8( &unwhite_header42[i], 8)
				);
//
			printf ("\n");




		}


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}
//////////////////////////////////////////////////////////////////////////////////////////
static void cb_rx_BASIC6( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx->data, 50 );
	memcpy ( prev_pkt2.data  , rx->data, 50 );

//	rx = ( struct usb_pkt_rx2 * ) rx_data;
	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = (3276799999 * rx->original_ch2) + 0xffffffff & le32toh (rx->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//////////////////////////////////
////			index = INDICES[clock & 0x3f];
//			index = INDICES[clock       ];
//			index += skipp;
//			index %= 127;
//
//			for(count = 0; count < length; count++)
//			{
//				/* unwhiten if whitened, otherwise just copy input to output */
//				unwhite_header3[count] = (1) ? white_header3[count] ^ WHITENING_DATA[index] : white_header3[count];
//				index += 1;
//				index %= 127;
//			}
////////////////////////////////


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );
		pkt_time  = (3276799999 * rx->original_ch ) + le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, err=%d, b=%d, sh=%d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, clkh=%u, clkh2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			b_info->err,
			b_info->byte,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
//			pkt_time, 
rx->clk100ns,
			b_info->pkt_clk100ns2,
rx->original_ch,
rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}
//////////////////////////////////////////////////////////////
static void cb_rx_BASIC7( struct usb_pkt_rx2 *rx1, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

struct usb_pkt_rx2 *rx_loc;

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx1->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx1->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx1->data, 50 );
//	memcpy ( prev_pkt2.data  , rx->data, 50 );

	rx_loc = ( struct usb_pkt_rx2 * ) &prev_pkt2;
	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 =  0xffffffff & le32toh (rx_loc->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//////////////////////////////////
////			index = INDICES[clock & 0x3f];
//			index = INDICES[clock       ];
//			index += skipp;
//			index %= 127;
//
//			for(count = 0; count < length; count++)
//			{
//				/* unwhiten if whitened, otherwise just copy input to output */
//				unwhite_header3[count] = (1) ? white_header3[count] ^ WHITENING_DATA[index] : white_header3[count];
//				index += 1;
//				index %= 127;
//			}
////////////////////////////////


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );
		pkt_time  = (3276799999 * rx_loc->original_ch ) + le32toh(rx_loc->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
//				b_info->channel2 	= rx_loc->channel;
				b_info->o_ch		= rx_loc->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx_loc->channel2;
				b_info->o_ch		= rx_loc->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx_loc->channel2;
		b_info->o_ch		= rx_loc->original_ch2 ;

	}

	b_info->channel2 	= rx_loc->channel2;

	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx_loc->channel;
	b_info->rssi		= rx_loc->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, err=%d, b=%d, sh=%d, CC=%d, LT_AD=%u, ch2=%u, cl=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			b_info->err,
			b_info->byte,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
//			pkt_time, 
rx_loc->clk100ns,
			b_info->pkt_clk100ns2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx_loc->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx_loc->original_ch;
	memcpy ( &prev_pkt2  , rx1, 64 );

}
////////////////////////////////////////////////////////////
static void cb_rx_BASIC604( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx->data, 50 );
	memcpy ( prev_pkt2.data  , rx->data, 50 );

//	rx = ( struct usb_pkt_rx2 * ) rx_data;
	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = (3276799999 * rx->original_ch2) + 0xffffffff & le32toh (rx->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//////////////////////////////////
////			index = INDICES[clock & 0x3f];
//			index = INDICES[clock       ];
//			index += skipp;
//			index %= 127;
//
//			for(count = 0; count < length; count++)
//			{
//				/* unwhiten if whitened, otherwise just copy input to output */
//				unwhite_header3[count] = (1) ? white_header3[count] ^ WHITENING_DATA[index] : white_header3[count];
//				index += 1;
//				index %= 127;
//			}
////////////////////////////////


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );
		pkt_time  = (3276799999 * rx->original_ch ) + le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, err=%d, b=%d, sh=%d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, clkh=%u, clkh2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			b_info->err,
			b_info->byte,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
//			pkt_time, 
rx->clk100ns,
			b_info->pkt_clk100ns2,
rx->original_ch,
rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}
/////////////////////////////////////////////////////
static void cb_rx_BASIC602( struct usb_pkt_rx2 *rx1, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;
struct usb_pkt_rx2 *rx_loc;
	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx1->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx1->channel); goto out;}

	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
	memcpy ( & rx_data [ 50 ], rx1->data, 50 );
//	memcpy ( prev_pkt2.data  , rx1->data, 50 );


//	rx_loc = ( struct usb_pkt_rx2 * ) rx_data;
	rx_loc = &prev_pkt2;

	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = (3276799999 * rx_loc->original_ch2) + 0xffffffff & le32toh (rx_loc->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;
//	ac_num_elems3 = find_known_lap6 (b_info, pico_info, rx_data, BANK_LEN, 5) ;
//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//////////////////////////////////
////			index = INDICES[clock & 0x3f];
//			index = INDICES[clock       ];
//			index += skipp;
//			index %= 127;
//
//			for(count = 0; count < length; count++)
//			{
//				/* unwhiten if whitened, otherwise just copy input to output */
//				unwhite_header3[count] = (1) ? white_header3[count] ^ WHITENING_DATA[index] : white_header3[count];
//				index += 1;
//				index %= 127;
//			}
////////////////////////////////


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
		pkt_time = le32toh(rx_loc->clk100ns) + (b_info->ac_offset_find3 * 10 );
//		pkt_time  = (3276799999 * rx->original_ch ) + le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx_loc->channel;
				b_info->o_ch		= rx_loc->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx_loc->channel2;
				b_info->o_ch		= rx_loc->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx_loc->channel2;
		b_info->o_ch		= rx_loc->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx_loc->channel;
	b_info->rssi		= rx_loc->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, err=%d, b=%d, sh=%d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, clkh=%u, clkh2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			b_info->err,
			b_info->byte,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
//			pkt_time, 
rx_loc->clk100ns,
			b_info->pkt_clk100ns2,
rx_loc->original_ch,
rx_loc->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx_loc->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx_loc->original_ch;

//	memcpy ( prev_pkt2.data  , rx1->data, 50 );
	memcpy ( &prev_pkt2  , rx1, sizeof ( struct usb_pkt_rx2 ) );
}
//////////////////////////////////////////////////////////
//static void cb_rx_BASIC61( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
static int cb_rx_BASIC61( struct _piconet_info_ *pico_info, struct buf_info *b_info, const uint8_t * full_buf, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, a1, b1, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	double slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];
	uint8_t local_full [ 64 * 4 ];
	struct usb_pkt_rx2 * rx, *curr_rx;

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}


//	switch ( bank )
//	{
//
//		case 0: 
//		memcpy ( &local_full [ 14 ], prev_pkt2.data, 50 );
//		rx = (struct usb_pkt_rx2 *) &full_buf [ 0 ];
//		memcpy ( &local_full [ 64 + 14 ], rx->data , 50 );
//		curr_rx = &prev_pkt2;		
//			break;
//
//		case 7:
////		rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * 7] );
//		memcpy ( &prev_pkt2, &full_buf [ PKT_LEN * 7], 64);
//			return;
//
//		default:
//		rx = (struct usb_pkt_rx2 *) &full_buf [ bank ];
//		memcpy ( &local_full[ 14 ], rx->data,  50);
//
//		rx = (struct usb_pkt_rx2 *) &full_buf [ bank +1];
//		memcpy ( &local_full[ 64+14 ], rx->data,  50);
//
//		curr_rx = (struct usb_pkt_rx2 *) &full_buf [ bank ];
//	}

uint8_t		ch2, prev_ch2 , curr_ch2;
uint32_t	prev_clkns2 , curr_clkns2;
int ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4; // sync = 8 bytes + 4 bits preamble
//int bits_in_this_buf64 = 0;
//uint8_t got_pkt = 0;
uint32_t buf_time = 0, prv_pkt_time = 0, lst_buf_time= 0 ;
uint64_t air_sync = 0 ;
int ii, byte = 0 , bit_errs = 0, shift, b = 0, d = 0, curr_d, max_ac_errs = 5, ac_offset_find4 ;


//////////////////////////////////////////////////
i = 0;
		while ( i < (64 + 7 + 14) )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;

			air_sync  = air_sync << 8;
			air_sync  = 0x00ffffffffffffff & ( air_sync | local_full [ i ] );

			if ( ii < 7 )
			{}
			else
			{
//			air_sync  = air_sync << 8;
//			air_sync  = 0x00ffffffffffffff & ( air_sync | local_full [ i ] );
////			for (byte = jump; byte < 50; byte++) 
////			{
				for ( shift = 0; shift < 8; shift++ )
				{

					bit_errs = local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );

					if  ( bit_errs  <= max_ac_errs )
					{	
						// timestamp is related to sync word
						byte = ( ii % 50);
						bits = (byte * 8) + shift;

						buf_time = curr_rx->clk100ns;

						pkt_time = buf_time + (bits * 10);

						if (prev_pkt_time > pkt_time)
							slots = (3276799999 + pkt_time - prv_pkt_time)/6250.0 ; 

						else    
							slots = (pkt_time - prv_pkt_time)/6250.0 ; 

						prv_pkt_time = pkt_time;

						ac_offset_find4 = bits;

						if ( pkt_time < curr_clkns2 )
						{
							ofst625 = (pkt_time - prev_clkns2);
							ch2	= prev_ch2;
						}
						else 
						{
							ofst625 = (pkt_time - curr_clkns2);
							ch2 	= curr_ch2;
						}

						printf ("Ac4 = %d, ch2=%u, p_time=%u, ofst625=%d, stls=%f\n", 
							ac_offset_find4, ch2, pkt_time, ofst625, slots);


					}
				}
			}






		++ i; ++ ii;
		}

return 0;
//	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
//	memcpy ( & rx_data [ 50 ], rx->data, 50 );
//	memcpy ( prev_pkt2.data  , rx->data, 50 );


	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

//	clk100ns2 = (3276799999 * rx->original_ch2) + 0xffffffff & le32toh (rx->clk100ns2);


//	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;

//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);

////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);

			hec       = 0xff & (hdr_data2 >> 10);

//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )

/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}


		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );
		pkt_time  = (3276799999 * rx->original_ch ) + le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, err=%d, b=%d, sh=%d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, clkh=%u, clkh2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			b_info->err,
			b_info->byte,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
//			pkt_time, 
rx->clk100ns,
			b_info->pkt_clk100ns2,
rx->original_ch,
rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}
//////////////////////////////////////////////////////
static void cb_rx_BASIC06( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, uint8_t *rx_data_in, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int z1, i, kk, byte = 0, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, skipp = 0, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

	memcpy ( & rx_data_in [ ( bank + 1 )  * SYM_LEN  ], prev_pkt2.data, 50 );
//	memcpy ( & rx_data [ 50 ], rx->data, 50 );
//	memcpy ( prev_pkt2.data  , rx->data, 50 );


	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = (3276799999 * rx->original_ch2) + 0xffffffff & le32toh (rx->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
//	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;
/////////////////////////////////////////////////////////////////
	uint64_t  * p1 ;
	int //count = -1 , 
		bit_errors, shift;

//	for (count = 0; count < 50; count++) 
	for (byte = global_jump; byte < 50; byte++) 
	{

		p1 		= (uint64_t *) & rx_data_in [ byte ];
		p1 [ 0 ] 	= 0xffffffffffffff00 & p1 [ 0 ];

		for ( shift = 0; shift < 8; shift++ )
		{
//			printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ shift ]   );
			bit_errors = count_bits ( p1 [ 0 ] ^ pico_info->reversed1 [ shift ]   );
			if  ( bit_errors <= max_ac_errors )
			{	
				b_info->ac_offset_find3 = (byte * 8) + shift;
				b_info->byte		= byte;
				b_info->shift		= shift;

				ac_num_elems3 		= 1;
				goto hdr_found;
//				return 1;
			}
		}
	}

hdr_found:
global_jump = 0;
/////////////////////////////////////////////////////////////////
//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		global_jump = b_info->byte + 15 ;

		unpack_symbols33		( &rx_data [ b_info->byte + 8 ], fec13_header3 );
		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

//		err_header  = unfec13_local ( syms + b_info->ac_offset + 68  , header, 18);

		for (clock = 0; clock < 64; clock++)
		{

			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);


////////////////////////////////
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//				for (a1 = 0; a1 < 18; a1++)
//					hdr_data2 |= ((uint32_t)unwhite_header3[a1] << a1);
/////////////////////////////////

//			hdr_data3 = 0x2ff & hdr_data2;
			hec       = 0xff & (hdr_data2 >> 10);

/////////////////////////////////
//			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data3), (0xff & hec)) ) )
			if (pico_info->UAP == (0xff & UAP_from_hec( (0x2ff & hdr_data2), (0xff & hec)) ) )
//			        for (b1 = 9; b1 >= 0; b1--) 
//				{
//			                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
//			                if (hec & 0x80)
//	                		        hec ^= 0x65;
//
//			                hec = (hec << 1) | (((hec >> 7) ^ (hdr_data3 >> b1)) & 0x01);
//			        }
//			hec3=	(hec & 0x80) >> 7 | 
//				(hec & 0x40) >> 5 | 
//				(hec & 0x20) >> 3 | 
//				(hec & 0x10) >> 1 | 
//				(hec & 0x08) << 1 | 
//				(hec & 0x04) << 3 | 
//				(hec & 0x02) << 5 | 
//				(hec & 0x01) << 7;
//			if (pico_info->UAP == ( 0xff & hec3 ) )
/////////////////////////////////
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);
				pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
				pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
				pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

				break ; // added recently
			}
		}

//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", oheader [ z1 ] );
//	printf ("\n");
//		for ( z1 = 0; z1 < 18; z1++ )
//		printf ("%u", unwhite_header3 [ z1 ] );
//	printf ("\n");

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset * 10 );
//		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );
		pkt_time  = (3276799999 * rx->original_ch ) + le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, clkh=%u, clkh2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
			pkt_time, 
			b_info->pkt_clk100ns2,
rx->original_ch,
rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf (", %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}

////////////////////////////////////////////////////////////////////////////////////////////////
int stream_rx_usb_BASIC ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
	int r, i, ii=0, jj =0, k=0, buf_pkts = 0, npkts=0, xfer_blocks, num_xfers, round_slts=0, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE], match_ctl [2];
	uint8_t ctrl_sig = 0, uber_sig_sent = 0, uber_sig2=0, sig_duration = 0, uber_std_speed =0;
	uint8_t prev_ch = 0;
	int8_t prev_ptype = -1;

	struct timeval currtime;
	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;


	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_set_clock (devh, 0 + (u32) ShmPTR->TargetCLK );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			cb_rx_BASIC (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
//			cb_rx_BASIC6 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			cb_rx_BASIC7 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			bank = (bank + 1) % NUM_BANKS;


//			if  (  1 == b_info.have_pkt ) 
			{	

				ii 					= npkts % PKT_BUF_SIZE;
				ShmPTR->basic_pkt_clk6_1	[ ii ] 	= b_info.clk6_1 ;
//				ShmPTR->basic_pkt_slts		[ ii ] 	= b_info.slts   ;
//				ShmPTR->basic_pkt_type		[ ii ] 	= b_info.ptype  ;
				ShmPTR->basic_pkt_625offset	[ ii ] 	= b_info.pkt_625ofst   ;
//				ShmPTR->basic_pkt_ptime		[ ii ]  = b_info.pkt_time;

				++ npkts;
				ShmPTR->basic_pkt_idx			= npkts;

			}


			if ( prev_ch != b_info.channel2 )
			{
				jj 					= buf_pkts % PKT_BUF_SIZE;
				ShmPTR->bufb_pkt_type		[ jj ]  = b_info.ptype  ;
				ShmPTR->bufb_pkt_ch		[ jj ]  = b_info.channel2  ;
				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
//				ShmPTR->bufb_pkt_och		[ jj ] 	= b_info.o_ch ;
//				ShmPTR->bufb_pkt_ptime		[ jj ] 	= b_info.pkt_time ;

				++ buf_pkts ;
				ShmPTR->bufb_pkt_idx			= buf_pkts;
			}

			else if ( prev_ch ==  b_info.channel2 )
			{

				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;

				if ( prev_ptype < b_info.ptype ) // collect longest pkt
//				if ( ShmPTR->buf_pkt_type [ jj ] <= b_info.ptype ) // collect longest pkt
				{
					ShmPTR->bufb_pkt_type 	[ jj ]	= b_info.ptype;
//					ShmPTR->bufb_pkt_ptime	[ jj ] 	= b_info.pkt_time ;
				}


			}

			prev_ch 	= b_info.channel2;
			prev_ptype	= b_info.ptype;
 
		}

		really_full = 0;
		fflush(stderr);


		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


//NUM_BANKS = 10
// Check 1 for 


//		if ( 1 == clk_found)
//		if ( 1 )
		{

		ctrl_sig = uber_ctrl_sig (ShmPTR, BASIC_HPNG);

//		if (  STANDARD_SPEED == ShmPTR->basic_pkt_status ) 
		switch ( ctrl_sig )
		{


			case SLOW_DOWN2:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_DOWN2);
//					}
				break;

			case SLOW_DOWN21:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN21;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN21);
//					}
				break;

			case SLOW_DOWN22:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
//					}
				break;

			case SLOW_DOWN23:
//					if ( ShmPTR->basic_pkt_status == STANDARD_SPEED && 0){
					match_ctl [0] = SLOW_DOWN23;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_DOWN23);
					uber_sig_sent = 1;
					printf ("reply********************************************************************=%d\n", SLOW_DOWN23);
//					}
				break;

			case STANDARD_SPEED:
					if ( 0 == uber_std_speed){
					match_ctl [0] = STANDARD_SPEED;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
					ShmPTR->basic_pkt_status = STANDARD_SPEED;
//					if ( STANDARD_SPEED == ShmPTR->adptv_pkt_status )
//						buf_pkts = 0;
					uber_std_speed = 1;
					}
				break;

			case SLOW_AND_STANDARD24:
					if ( 0 == uber_sig2){
					match_ctl [0] = SLOW_AND_STANDARD24;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_AND_STANDARD24);
					uber_sig2 = 1;
					}
				break;


			default:

					if ( 2 == sig_duration)
					{	
						uber_sig_sent = 0;
						sig_duration = 0;
					}
				
					++ sig_duration ;
			}
		}

	}
	
out:

return 0;

}
/////////////////////////////////
static int local_count_bits (uint64_t n)
{
	int i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
}
///////////////////////////
int analyze_pkt_hdr ( struct _rx_info *rx_info, uint8_t *local_full, int i0, int hdr_bytes  )
{
	uint64_t hdr = 0;
	int i = i0 + 1, b, k = hdr_bytes;
//	while ( ( i < 512) && (k < 8) )
	while ( ( i < 512) && (k < 8) )
	{
		b = i % 64;
		i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;
		hdr = hdr << 8;
		hdr = hdr | local_full [ i ];

		++i; ++ k; 
	}

	rx_info->hdr_bytes = k;


	return 0;
}
////////////////////////////////////////////////////////////
int stream_rx_usb_BASIC03 ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
//BUFFER_SIZE 102400
	int r, i, ii=0, jj =0, k=0, buf_pkts = 0, npkts=0, xfer_blocks, num_xfers, round_slts=0, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE], match_ctl [2];
	uint8_t ctrl_sig = 0, uber_sig_sent = 0, uber_sig2=0, sig_duration = 0, uber_std_speed =0;
	uint8_t prev_ch = 0;
	int8_t prev_ptype = -1;

	struct timeval currtime;
	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;

	uint8_t local_full [ BUFFER_SIZE ];

	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_set_clock (devh, 0 + (u32) ShmPTR->TargetCLK );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}

uint8_t		ch2, prev_ch2 , curr_ch2;
uint32_t	prev_clkns2 , curr_clkns2;
int ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4; // sync = 8 bytes + 4 bits preamble
//int bits_in_this_buf64 = 0;
//uint8_t got_pkt = 0;
uint32_t buf_time = 0, pkt_time = 0, prv_pkt_time = 0, lst_buf_time= 0 ;
uint64_t air_sync = 0 ;
int byte = 0 , bit_errs = 0, shift, b = 0, d = 0, curr_d, ac_num_elems3 = 0, max_ac_errs = 5, ac_offset_find4 ;
double slots = 0;

	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }


//		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);
//			memcpy ( &b_info.bu  [ ( PKT_LEN * (i+1) ) + 14 ] , rx->data  ,50 );
//			b_info.buf_time = rx->clk100ns;

//			cb_rx_BASIC61 ( pico_info, &b_info, full_buf, i, PRNT_MODE_ALL );
//			cb_rx_BASIC6 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
printf ("*************************\n");
			cb_rx_BASIC602( rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
printf ("*************************\n");
printf ("===========================\n");
			cb_rx_BASIC6 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
printf ("===========================\n");
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			bank = (bank + 1) % NUM_BANKS;

//
//
////			if  (  1 == b_info.have_pkt ) 
//			{	
//
//				ii 					= npkts % PKT_BUF_SIZE;
//				ShmPTR->basic_pkt_clk6_1	[ ii ] 	= b_info.clk6_1 ;
////				ShmPTR->basic_pkt_slts		[ ii ] 	= b_info.slts   ;
////				ShmPTR->basic_pkt_type		[ ii ] 	= b_info.ptype  ;
//				ShmPTR->basic_pkt_625offset	[ ii ] 	= b_info.pkt_625ofst   ;
////				ShmPTR->basic_pkt_ptime		[ ii ]  = b_info.pkt_time;
//
//				++ npkts;
//				ShmPTR->basic_pkt_idx			= npkts;
//
//			}
//
//
//			if ( prev_ch != b_info.channel2 )
//			{
//				jj 					= buf_pkts % PKT_BUF_SIZE;
//				ShmPTR->bufb_pkt_type		[ jj ]  = b_info.ptype  ;
//				ShmPTR->bufb_pkt_ch		[ jj ]  = b_info.channel2  ;
//				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
////				ShmPTR->bufb_pkt_och		[ jj ] 	= b_info.o_ch ;
////				ShmPTR->bufb_pkt_ptime		[ jj ] 	= b_info.pkt_time ;
//
//				++ buf_pkts ;
//				ShmPTR->bufb_pkt_idx			= buf_pkts;
//			}
//
//			else if ( prev_ch ==  b_info.channel2 )
//			{
//
//				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
//
//				if ( prev_ptype < b_info.ptype ) // collect longest pkt
////				if ( ShmPTR->buf_pkt_type [ jj ] <= b_info.ptype ) // collect longest pkt
//				{
//					ShmPTR->bufb_pkt_type 	[ jj ]	= b_info.ptype;
////					ShmPTR->bufb_pkt_ptime	[ jj ] 	= b_info.pkt_time ;
//				}
//
//
//			}
//
			prev_ch 	= b_info.channel2;
			prev_ptype	= b_info.ptype;
 
		}

		rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * 7);
		memcpy ( &b_info.bu  [ 14 ] , rx->data  ,50 );
		b_info.buf_time = rx->clk100ns;
printf ("===========================\n");
		really_full = 0;
		fflush(stderr);


		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


//NUM_BANKS = 10
// Check 1 for 


////		if ( 1 == clk_found)
////		if ( 1 )
//		{
//
//		ctrl_sig = uber_ctrl_sig (ShmPTR, BASIC_HPNG);
//
////		if (  STANDARD_SPEED == ShmPTR->basic_pkt_status ) 
//		switch ( ctrl_sig )
//		{
//
//
//			case SLOW_DOWN2:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN2;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_DOWN2);
////					}
//				break;
//
//			case SLOW_DOWN21:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN21;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN21);
////					}
//				break;
//
//			case SLOW_DOWN22:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN2;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
////					}
//				break;
//
//			case SLOW_DOWN23:
////					if ( ShmPTR->basic_pkt_status == STANDARD_SPEED && 0){
//					match_ctl [0] = SLOW_DOWN23;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_DOWN23);
//					uber_sig_sent = 1;
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN23);
////					}
//				break;
//
//			case STANDARD_SPEED:
//					if ( 0 == uber_std_speed){
//					match_ctl [0] = STANDARD_SPEED;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
//					ShmPTR->basic_pkt_status = STANDARD_SPEED;
////					if ( STANDARD_SPEED == ShmPTR->adptv_pkt_status )
////						buf_pkts = 0;
//					uber_std_speed = 1;
//					}
//				break;
//
//			case SLOW_AND_STANDARD24:
//					if ( 0 == uber_sig2){
//					match_ctl [0] = SLOW_AND_STANDARD24;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_AND_STANDARD24);
//					uber_sig2 = 1;
//					}
//				break;
//
//
//			default:
//
//					if ( 2 == sig_duration)
//					{	
//						uber_sig_sent = 0;
//						sig_duration = 0;
//					}
//				
//					++ sig_duration ;
//			}
//		}

	}
	
out:

return 0;

}

///////////////////////////////////////////////////////////
int stream_rx_usb_BASIC01 ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
//BUFFER_SIZE 102400
	int r, i, ii=0, jj =0, k=0, buf_pkts = 0, npkts=0, xfer_blocks, num_xfers, round_slts=0, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE], match_ctl [2];
	uint8_t ctrl_sig = 0, uber_sig_sent = 0, uber_sig2=0, sig_duration = 0, uber_std_speed =0;
	uint8_t prev_ch = 0;
	int8_t prev_ptype = -1;

	struct timeval currtime;
	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;

	uint8_t local_full [ BUFFER_SIZE ];

	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_set_clock (devh, 0 + (u32) ShmPTR->TargetCLK );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}

uint8_t		ch2, prev_ch2 , curr_ch2;
uint32_t	prev_clkns2 , curr_clkns2;
int ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4; // sync = 8 bytes + 4 bits preamble
//int bits_in_this_buf64 = 0;
//uint8_t got_pkt = 0;
uint32_t buf_time = 0, pkt_time = 0, prv_pkt_time = 0, lst_buf_time= 0 ;
uint64_t air_sync = 0 ;
int byte = 0 , bit_errs = 0, shift, b = 0, d = 0, curr_d, ac_num_elems3 = 0, max_ac_errs = 5, ac_offset_find4 ;
double slots = 0;

	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);
			memcpy ( &local_full [ (PKT_LEN * i) + 14 ], rx->data,50);

		}

printf ("*************************xfer_blocks=%d\n", xfer_blocks);
		i = 0 ; ii = 0; ac_num_elems3 = 0; ac_offset_find4 = -1;
		while ( i < 512 )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;
///////////////////////////////////////////////////////////////////////////////////
			if ( curr_d != d)
			{
				curr_d = d;
				rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);		
				if ( curr_ch2 != rx->channel2 )
				{
					prev_ch2 = curr_ch2;
					prev_clkns2 = curr_clkns2;

					curr_ch2 = rx->channel2;
					curr_clkns2 = rx->clk100ns2;
				// 
				}
			}

///////////////////////////////////////////////////////////////////////////////

//			if 1 == missing_hdr_flag 
// 			missing_hdr_flag = 0;
//			get the rest of the hdr from the new incoming full_buffer
// 			analyze_pkt_hdr ( local_full, i );
// 			we can do i jump here i = i + 35; --i; // because we have ++ i
// 			we got a pkt flag, got_pkt = 1;

//			else
			{
			air_sync  = air_sync << 8;
//			air_sync  = 0x00ffffffffffffff & ( air_sync | full_buf [ i ] );
			air_sync  = 0x00ffffffffffffff & ( air_sync | local_full [ i ] );
//			for (byte = jump; byte < 50; byte++) 
//			{
				for ( shift = 0; shift < 8; shift++ )
				{

					bit_errs = local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );
//					bit_errs = local_count_bits ( air_sync  ^ pico_info->air_order_preamble_syncword [ shift ]   );

					if  ( bit_errs  <= max_ac_errs )
					{	
						// timestamp is related to sync word
						   byte = ( ii % 50);
						   bits = (byte * 8) - (spec_bits - shift);
//						   bits = (byte * 8) + shift;
						if (bits < 0)	//	then the timestamp must be in the prev buf
						{	bits = 400 + bits ;
							if (ii < 50) // ii is in the first buf64
								buf_time  = lst_buf_time ;

							else 
							{
								rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * (d -1 ) );
								buf_time = rx->clk100ns ;
							}
						}

						else 
						{
							rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);
							buf_time = rx->clk100ns ;
						}

						pkt_time = buf_time + (bits * 10);

						if (prev_pkt_time > pkt_time)
							slots = (3276799999 + pkt_time - prv_pkt_time)/6250.0 ; 

						else    
							slots = (pkt_time - prv_pkt_time)/6250.0 ; 

						prv_pkt_time = pkt_time;

						ac_offset_find4 = bits;

						if ( pkt_time < curr_clkns2 )
						{
							ofst625 = (pkt_time - prev_clkns2);
							ch2	= prev_ch2;
						}
						else 
						{
							ofst625 = (pkt_time - curr_clkns2);
							ch2 	= curr_ch2;
						}

						printf ("Ac4 = %d, ch2=%u, err=%d, p_time=%u, ofst625=%d, stls=%f\n", 
							ac_offset_find4, ch2, bit_errs, pkt_time, ofst625, slots);

///////////////////////////////////////////////////////////////////////////////////////////////////////

						if ( 392 < ii ) // 399 - 7 = 392 // 7 bytes is the max required for the hdr
						{
						// missing_hdr_flag = 1;
						// get what is available from the hdr
						}

						else
						{
						// missing_hdr_flag = 0;
						// get the entire header and do analysis
						// analyze_pkt_hdr ( local_full, i );
						// we can do i jump here i = i + 35; --i; // because we have ++ i
						// we got a pkt flag, got_pkt = 1;

						}

					}
				}
			}





//			}
//			if ( 1 == got_pkt && 8 == bytes_in_hdr )
			{
//				got_pkt = 0;
//				bytes_in_hdr = 0;

//				analyze relation to other pkts: 
//	1- dist, 
//	2- ofst625, this should be calculated wrt curr clk100ns2;
//	if we have 2 clkns2, then we find to which one a pkt belongs
//	then we find ofst625

//	3- 



// 			finally insert pkt in ShMemory

			}


		++ i; ++ ii;
		}
///////////////////////////////////////////////////
//			these two must be outside the loop because we only need them if we need some info from prev but of 64 * 8
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * 7 );
//			lst_pkt_time = pkt_time ;
			lst_buf_time = rx->clk100ns;

/////////////////////////////////////////////////
printf ("*************************\n");
printf ("===========================\n");
//		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

			cb_rx_BASIC6 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			bank = (bank + 1) % NUM_BANKS;

//
//
////			if  (  1 == b_info.have_pkt ) 
//			{	
//
//				ii 					= npkts % PKT_BUF_SIZE;
//				ShmPTR->basic_pkt_clk6_1	[ ii ] 	= b_info.clk6_1 ;
////				ShmPTR->basic_pkt_slts		[ ii ] 	= b_info.slts   ;
////				ShmPTR->basic_pkt_type		[ ii ] 	= b_info.ptype  ;
//				ShmPTR->basic_pkt_625offset	[ ii ] 	= b_info.pkt_625ofst   ;
////				ShmPTR->basic_pkt_ptime		[ ii ]  = b_info.pkt_time;
//
//				++ npkts;
//				ShmPTR->basic_pkt_idx			= npkts;
//
//			}
//
//
//			if ( prev_ch != b_info.channel2 )
//			{
//				jj 					= buf_pkts % PKT_BUF_SIZE;
//				ShmPTR->bufb_pkt_type		[ jj ]  = b_info.ptype  ;
//				ShmPTR->bufb_pkt_ch		[ jj ]  = b_info.channel2  ;
//				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
////				ShmPTR->bufb_pkt_och		[ jj ] 	= b_info.o_ch ;
////				ShmPTR->bufb_pkt_ptime		[ jj ] 	= b_info.pkt_time ;
//
//				++ buf_pkts ;
//				ShmPTR->bufb_pkt_idx			= buf_pkts;
//			}
//
//			else if ( prev_ch ==  b_info.channel2 )
//			{
//
//				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
//
//				if ( prev_ptype < b_info.ptype ) // collect longest pkt
////				if ( ShmPTR->buf_pkt_type [ jj ] <= b_info.ptype ) // collect longest pkt
//				{
//					ShmPTR->bufb_pkt_type 	[ jj ]	= b_info.ptype;
////					ShmPTR->bufb_pkt_ptime	[ jj ] 	= b_info.pkt_time ;
//				}
//
//
//			}
//
			prev_ch 	= b_info.channel2;
			prev_ptype	= b_info.ptype;
 
		}
printf ("===========================\n");
		really_full = 0;
		fflush(stderr);


		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


//NUM_BANKS = 10
// Check 1 for 


////		if ( 1 == clk_found)
////		if ( 1 )
//		{
//
//		ctrl_sig = uber_ctrl_sig (ShmPTR, BASIC_HPNG);
//
////		if (  STANDARD_SPEED == ShmPTR->basic_pkt_status ) 
//		switch ( ctrl_sig )
//		{
//
//
//			case SLOW_DOWN2:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN2;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_DOWN2);
////					}
//				break;
//
//			case SLOW_DOWN21:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN21;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN21);
////					}
//				break;
//
//			case SLOW_DOWN22:
////					if ( 1 == uber_std_speed){
//					match_ctl [0] = SLOW_DOWN2;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
////					}
//				break;
//
//			case SLOW_DOWN23:
////					if ( ShmPTR->basic_pkt_status == STANDARD_SPEED && 0){
//					match_ctl [0] = SLOW_DOWN23;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_DOWN23);
//					uber_sig_sent = 1;
//					printf ("reply********************************************************************=%d\n", SLOW_DOWN23);
////					}
//				break;
//
//			case STANDARD_SPEED:
//					if ( 0 == uber_std_speed){
//					match_ctl [0] = STANDARD_SPEED;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
//					ShmPTR->basic_pkt_status = STANDARD_SPEED;
////					if ( STANDARD_SPEED == ShmPTR->adptv_pkt_status )
////						buf_pkts = 0;
//					uber_std_speed = 1;
//					}
//				break;
//
//			case SLOW_AND_STANDARD24:
//					if ( 0 == uber_sig2){
//					match_ctl [0] = SLOW_AND_STANDARD24;
//					cmd_do_something(devh, match_ctl, 1);
//					printf ("reply=%d\n", SLOW_AND_STANDARD24);
//					uber_sig2 = 1;
//					}
//				break;
//
//
//			default:
//
//					if ( 2 == sig_duration)
//					{	
//						uber_sig_sent = 0;
//						sig_duration = 0;
//					}
//				
//					++ sig_duration ;
//			}
//		}

	}
	
out:

return 0;

}
///////////////////////////////////////////////////////////////////
//if  (512 > 102400)
//PKT_LEN       64
#define DO_USB_SETTING \
	int xfer_size = XFER_LEN; uint16_t num_blocks = 0;\
	if (xfer_size > BUFFER_SIZE)\
		xfer_size = BUFFER_SIZE;\
	xfer_blocks = xfer_size / PKT_LEN;\
	xfer_size = xfer_blocks * PKT_LEN;\
	num_xfers = num_blocks / xfer_blocks;\
	num_blocks = num_xfers * xfer_blocks;\
	empty_buf = &rx_buf1[0];\
	full_buf = &rx_buf2[0];\
	really_full = 0;\
	rx_xfer = libusb_alloc_transfer(0);\
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf, xfer_size, cb_xfer, NULL, TIMEOUT);
///////////////////////////////////////////////////////////
int stream_rx_usb_BASIC05 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_B, struct _piconet_info_ *pico_info )
{
//BUFFER_SIZE 102400
int 		r, i, ii=0, xfer_blocks, num_xfers, bank = 0,
		ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4,
		byte = 0 , bit_errs = 0, shift, b = 0, d = 0, curr_d, max_ac_errs = 5;

uint8_t 	rx_buf1[BUFFER_SIZE], 
		rx_buf2[BUFFER_SIZE],
		local_full [ BUFFER_SIZE ];

int8_t  	curr_rssi ;
uint8_t		new_slt = 0, cl, curr_cl, prev_cl, ch2, prev_ch2, curr_ch2 ,
		ctrl_sig = 0, uber_sig_sent = 0, uber_std_speed =0, match_ctl [2];

uint32_t 	buf_time = 0, pkt_tm = 0, prv_pkt_tm = 0, lst_buf_time= 0 , prev_clkns2 , curr_clkns2;
uint64_t 	air_sync = 0 ;
double 		slots = 0;


struct usb_pkt_rx2 *rx;
/////////////////////////////////////////
struct _slt_buf slt_buf1, slt_buf2, speed_ctrl_slt, *prev_slt, *curr_slt, *tmp_slt;

prev_slt 	= &slt_buf1;
curr_slt	= &slt_buf2;

size_t slt_buf = sizeof ( struct _slt_buf );

//////////////////////////////////////////
	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */

	DO_USB_SETTING;

	cmd_set_clock (devh, 0 + (u32) pico_info->TargetCLK          );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);
			memcpy ( &local_full [ (PKT_LEN * i) + 14 ], rx->data,50);

		}

		i = 0 ; ii = 0; 
		while ( i < 512 )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;
///////////////////////////////////////////////////////////////////////////////////
			if ( curr_d != d)
			{
				curr_d = d;
				rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);

				if ( 0 == curr_slt->slt_rssi )
					curr_slt->slt_rssi = rx->rssi_max;

				// for each ch there one rssi taken at the second slt
				// for each ch we have two pkts, and thus, two ofst625 (ofst625 is -1 initially)
 
				if ( curr_ch2 != rx->channel2 )
				{

					new_slt = 1;
					// do swap
					tmp_slt = curr_slt;
					curr_slt = prev_slt;
					prev_slt = tmp_slt;

					curr_slt->slt_ch = rx->channel2;
					curr_slt->slt_rssi = 0;
					curr_slt->ofst625_1 = 0;
					curr_slt->ofst625_2 = 0;
					
					prev_ch2 = curr_ch2;
					prev_clkns2 = curr_clkns2;
					prev_cl	= curr_cl;

					curr_ch2 = rx->channel2;
					curr_clkns2 = rx->clk100ns2;
					curr_cl = rx->channel;

				}
			}

///////////////////////////////////////////////////////////////////////////////

//			if 1 == missing_hdr_flag 
// 			missing_hdr_flag = 0;
//			get the rest of the hdr from the new incoming full_buffer
// 			analyze_pkt_hdr ( local_full, i );
// 			we can do i jump here i = i + 35; --i; // because we have ++ i
// 			we got a pkt flag, got_pkt = 1;

//			else
//			{
			air_sync  = air_sync << 8;
//			air_sync  = 0x00ffffffffffffff & ( air_sync | full_buf [ i ] );
			air_sync  = 0x00ffffffffffffff & ( air_sync | local_full [ i ] );

			for ( shift = 0; shift < 8; shift++ )
			{

				bit_errs = 
				local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );

				if  ( bit_errs  <= max_ac_errs )
				{	
					// timestamp is related to sync word
					byte = ( ii % 50);
					bits = (byte * 8) - (spec_bits - shift);

					if (bits < 0)	
					// then the timestamp must be in the prev buf
					{	
						bits = 400 + bits ;
						if (ii < 50) // ii is in the first buf64
						{	
							rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * (0 ) );
							buf_time = rx->clk100ns - 4000;
						}

						else 
						{
							rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * (d -1 ) );
							buf_time = rx->clk100ns ;
						}
					}

					// else it is in this buf
					else 
					{
						rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);
						buf_time = rx->clk100ns ;
					}

					pkt_tm = buf_time + (bits * 10);

					if (prv_pkt_tm > pkt_tm)
						slots = (3276799999 + pkt_tm - prv_pkt_tm)/6250.0 ; 

					else    
						slots = (pkt_tm - prv_pkt_tm)/6250.0 ; 

					prv_pkt_tm = pkt_tm;


					if (  curr_clkns2 < pkt_tm )
					{
						ofst625 = (pkt_tm - curr_clkns2);
						ch2 	= curr_ch2;
						cl	= prev_cl;

						if ( 0 == curr_slt->ofst625_1 )
							curr_slt->ofst625_1 = ofst625;
						else 
							curr_slt->ofst625_2 = ofst625;
					}

					else if ( ( prev_clkns2 < pkt_tm ) && ( pkt_tm < curr_clkns2 ) )
					{
						ofst625 = (pkt_tm - prev_clkns2);
						ch2	= prev_ch2;
						cl	= curr_cl;

						new_slt = 2;
						if ( 0 == prev_slt->ofst625_1 )
							prev_slt->ofst625_1 = ofst625;
						else 
							prev_slt->ofst625_2 = ofst625;

					}


			printf ("Ac4 = %d, cl=%u, ch2=%u, err=%d, p_time=%u, ofst625=%d, stls=%f\n", 
				bits, rx->channel, ch2, bit_errs, pkt_tm, ofst625, slots);


///////////////////////////////////////////////////////////////////////////////////////////////////////
					if ( 392 < ii ) // 399 - 7 = 392 // 7 bytes is the max required for the hdr
					{
					// missing_hdr_flag = 1;
					// get what is available from the hdr
					}

					else
					{
					// missing_hdr_flag = 0;
					// get the entire header and do analysis
					// analyze_pkt_hdr ( local_full, i );
					// we can do i jump here i = i + 35; --i; // because we have ++ i
					// we got a pkt flag, got_pkt = 1;
					}

				}
			}
//		}

//////////////////////////////////////////////////////////////
		if ( 0 < new_slt )
		{

			print_slt ( prev_slt );
			printf ("----%d\n", add_new_slt2 ( ShmPTR_B, prev_slt, new_slt ) );
			new_slt = 0;

			if ( ( 0 != prev_slt->ofst625_1) && (0 !=prev_slt->ofst625_2 ) )
			{
				speed_ctrl_slt.ofst625_1 = prev_slt->ofst625_1;
				speed_ctrl_slt.ofst625_2 = prev_slt->ofst625_2;
			}

		}
//////////////////////////////////////////////////////////////

//			if ( 1 == got_pkt && 8 == bytes_in_hdr )
//			{
//				got_pkt = 0;
//				bytes_in_hdr = 0;
//
//			}


		++ i; ++ ii;
		}
///////////////////////////////////////////////////
//		these two must be outside the loop because we only need them if we need some info from prev but of 64 * 8
		rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * 7 );
		lst_buf_time = rx->clk100ns;

/////////////////////////////////////////////////
printf ("*************************\n");

		really_full = 0;
		fflush(stderr);


		ctrl_sig = uber_ctrl_sig5 ( &speed_ctrl_slt  );

		if ( 0 != ctrl_sig )
		{

		speed_ctrl_slt.ofst625_1 = 0;
		speed_ctrl_slt.ofst625_2 = 0;

		switch ( ctrl_sig )	{

		case SLOW_DOWN22:
			if ( 2 <= uber_std_speed){
			match_ctl [0] = SLOW_DOWN2;
			printf ("We speed ctrl1\n");
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
			}
			break;

		case STANDARD_SPEED:
			++ uber_std_speed;
			if ( 2 == uber_std_speed){
			match_ctl [0] = STANDARD_SPEED;
			printf ("We speed ctrl2\n");
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
			}
			break;

		}
		ctrl_sig = 0;
		}



		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


	}
	
out:

return 0;

}
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
int stream_rx_usb_ADPTV05 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_A, struct _piconet_info_ *pico_info)
{
//BUFFER_SIZE 102400
int 		r, i, ii=0, xfer_blocks, num_xfers, bank = 0,
		ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4,
		byte = 0 , bit_errs = 0, shift, b = 0, d = 0, curr_d, max_ac_errs = 5;

uint8_t 	rx_buf1[BUFFER_SIZE], 
		rx_buf2[BUFFER_SIZE],
		local_full [ BUFFER_SIZE ], afh_map [10];

int8_t  	curr_rssi ;
uint8_t		new_slt = 0, cl, curr_cl, prev_cl, ch2, prev_ch2, curr_ch2 ,
		ctrl_sig = 0, uber_sig_sent = 0, uber_std_speed =0, match_ctl [2];

uint32_t 	buf_tm = 0, pkt_tm = 0, prv_pkt_tm = 0, lst_buf_tm= 0 , prev_clkns2 , curr_clkns2;
uint64_t 	air_sync = 0 ;
double 		slots = 0;


struct usb_pkt_rx2 *rx;
/////////////////////////////////////////
struct _slt_buf slt_buf1, slt_buf2, speed_ctrl_slt, *prev_slt, *curr_slt, *tmp_slt;

prev_slt 	= &slt_buf1;
curr_slt	= &slt_buf2;

size_t slt_buf = sizeof ( struct _slt_buf );

//////////////////////////////////////////
	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */

	DO_USB_SETTING;

	cmd_set_clock (devh, 0 + (u32) pico_info->TargetCLK   );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);
			memcpy ( &local_full [ (PKT_LEN * i) + 14 ], rx->data,50);

		}

		i = 0 ; ii = 0; 
		while ( i < 512 )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;
///////////////////////////////////////////////////////////////////////////////////
			if ( curr_d != d)
			{
				curr_d = d;
				rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);

				if ( 0 == curr_slt->slt_rssi )
					curr_slt->slt_rssi = rx->rssi_max;

				// for each ch there one rssi taken at the second slt
				// for each ch we have two pkts, and thus, two ofst625 (ofst625 is -1 initially)
 
				if ( curr_ch2 != rx->channel2 )
				{

					new_slt = 1;
					// do swap
					tmp_slt = curr_slt;
					curr_slt = prev_slt;
					prev_slt = tmp_slt;

					curr_slt->slt_ch = rx->channel2;
					curr_slt->slt_rssi = 0;
					curr_slt->ofst625_1 = 0;
					curr_slt->ofst625_2 = 0;

					prev_ch2 = curr_ch2;
					prev_clkns2 = curr_clkns2;
					prev_cl	= curr_cl;

					curr_ch2 = rx->channel2;
					curr_clkns2 = rx->clk100ns2;
					curr_cl = rx->channel;

				}
			}

///////////////////////////////////////////////////////////////////////////////

//			if 1 == missing_hdr_flag 
// 			missing_hdr_flag = 0;
//			get the rest of the hdr from the new incoming full_buffer
// 			analyze_pkt_hdr ( local_full, i );
// 			we can do i jump here i = i + 35; --i; // because we have ++ i
// 			we got a pkt flag, got_pkt = 1;

//			else
//			{
			air_sync  = air_sync << 8;
//			air_sync  = 0x00ffffffffffffff & ( air_sync | full_buf [ i ] );
			air_sync  = 0x00ffffffffffffff & ( air_sync | local_full [ i ] );

			for ( shift = 0; shift < 8; shift++ )
			{

				bit_errs = 
				local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );

				if  ( bit_errs  <= max_ac_errs )
				{	
					// timestamp is related to sync word
					byte = ( ii % 50);
					bits = (byte * 8) - (spec_bits - shift);

					if (bits < 0)	
					// then the timestamp must be in the prev buf
					{	
						bits = 400 + bits ;
						if (ii < 50) // ii is in the first buf64
						{	
							rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * (0 ) );
							buf_tm = rx->clk100ns - 4000;
						}

						else 
						{
							rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * (d -1 ) );
							buf_tm = rx->clk100ns ;
						}
					}

					// else it is in this buf
					else 
					{
						rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * d);
						buf_tm = rx->clk100ns ;
					}

					pkt_tm = buf_tm + (bits * 10);

					if (prv_pkt_tm > pkt_tm)
						slots = (3276799999 + pkt_tm - prv_pkt_tm)/6250.0 ; 

					else    
						slots = (pkt_tm - prv_pkt_tm)/6250.0 ; 

					prv_pkt_tm = pkt_tm;


					if (  curr_clkns2 < pkt_tm )
					{
						ofst625 = (pkt_tm - curr_clkns2);
						ch2 	= curr_ch2;
						cl	= prev_cl;

						if ( 0 == curr_slt->ofst625_1 )
							curr_slt->ofst625_1 = ofst625;
						else 
							curr_slt->ofst625_2 = ofst625;
					}

					else if ( ( prev_clkns2 < pkt_tm ) && ( pkt_tm < curr_clkns2 ) )
					{
						ofst625 = (pkt_tm - prev_clkns2);
						ch2	= prev_ch2;
						cl	= curr_cl;

						new_slt = 2;
						if ( 0 == prev_slt->ofst625_1 )
							prev_slt->ofst625_1 = ofst625;
						else 
							prev_slt->ofst625_2 = ofst625;

					}


			printf ("Ac4 = %d, cl=%u, ch2=%u, err=%d, p_time=%u, ofst625=%d, stls=%f\n", 
				bits, rx->channel, ch2, bit_errs, pkt_tm, ofst625, slots);


///////////////////////////////////////////////////////////////////////////////////////////////////////
					if ( 392 < ii ) // 399 - 7 = 392 // 7 bytes is the max required for the hdr
					{
					// missing_hdr_flag = 1;
					// get what is available from the hdr
					}

					else
					{
					// missing_hdr_flag = 0;
					// get the entire header and do analysis
					// analyze_pkt_hdr ( local_full, i );
					// we can do i jump here i = i + 35; --i; // because we have ++ i
					// we got a pkt flag, got_pkt = 1;
					}

				}
			}
//		}

//////////////////////////////////////////////////////////////
		if ( 0 < new_slt )
		{

			print_slt ( prev_slt );
			printf ("----%d\n", add_new_slt2 ( ShmPTR_A, prev_slt, new_slt ) );
			new_slt = 0;

			if ( ( 0 != prev_slt->ofst625_1) && (0 !=prev_slt->ofst625_2 ) )
			{
				speed_ctrl_slt.ofst625_1 = prev_slt->ofst625_1;
				speed_ctrl_slt.ofst625_2 = prev_slt->ofst625_2;
			}

		}

//////////////////////////////////////////////////////////////

//			if ( 1 == got_pkt && 8 == bytes_in_hdr )
//			{
//				got_pkt = 0;
//				bytes_in_hdr = 0;
//			}


		++ i; ++ ii;
		}
///////////////////////////////////////////////////
//		these two must be outside the loop because we only need them if we need some info from prev but of 64 * 8
		rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * 7 );
		lst_buf_tm = rx->clk100ns;

/////////////////////////////////////////////////
printf ("*************************\n");

		really_full = 0;
		fflush(stderr);

// important note: don't talk to ubertooth in the above loop!!!
		ctrl_sig = uber_ctrl_sig5 ( &speed_ctrl_slt  );

		if ( 0 != ctrl_sig )
		{

		speed_ctrl_slt.ofst625_1 = 0;
		speed_ctrl_slt.ofst625_2 = 0;

		switch ( ctrl_sig )	{

		case SLOW_DOWN22:
			if ( 2 <= uber_std_speed){
			match_ctl [0] = SLOW_DOWN2;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
			}
			break;

		case STANDARD_SPEED:
			++ uber_std_speed;
			if ( 2 == uber_std_speed){
			match_ctl [0] = STANDARD_SPEED;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
			}
			break;

		}
		ctrl_sig = 0;
		}



		if ( AFH_GT_FILLED2 == ShmPTR_A->AFH_status) 
		{

//			SHM2_get_GH_afh ( ShmPTR_A, afh_map );

			printf ("afterwe got afh\n");

//			cmd_set_afh_map	(devh, afh_map);
			cmd_set_afh_map	(devh, ShmPTR_A->GT_afh);

		}

		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


	}
	
out:

return 0;

}
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
int stream_rx_usb_ADPTV06 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_A, struct _piconet_info_ *pico_info)
{
//BUFFER_SIZE 102400
int 		r, i, ii=0, xfer_blocks, num_xfers, 
		ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4,
		bit_errs = 0, shift, b = 0, d = 0, curr_d, max_ac_errs = 5;

uint8_t 	rx_buf1[BUFFER_SIZE], 
		rx_buf2[BUFFER_SIZE], afh_map [10];

int8_t  	curr_rssi ;
uint8_t		new_slt = 0, cl, curr_cl, prev_cl, ch2, prev_ch2, curr_ch2 ,
		ctrl_sig = 0, uber_std_speed =0, match_ctl [2];

uint32_t 	buf_tm = 0, pkt_tm = 0, prv_pkt_tm = 0, lst_buf_tm= 0 , prev_clkns2 , curr_clkns2;
uint64_t 	air_sync = 0 ;
double 		slots = 0;


struct usb_pkt_rx2 *rx;
/////////////////////////////////////////
struct _slt_buf slt_buf1, slt_buf2, speed_ctrl_slt, *prev_slt, *curr_slt, *tmp_slt;

prev_slt 	= &slt_buf1;
curr_slt	= &slt_buf2;
//////////////////////////////////////////
	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */

	DO_USB_SETTING;

	cmd_set_clock (devh, 0 + (u32) pico_info->TargetCLK   );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		i = 0 ; ii = 0; 
		while ( i < 512 )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;
///////////////////////////////////////////////////////////////////////////////////
			if ( curr_d != d)
			{
				curr_d = d;
				rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * d] );

				if ( 0 == curr_slt->slt_rssi )
					curr_slt->slt_rssi = rx->rssi_max;

				// for each ch there one rssi taken at the second slt
				// for each ch we have two pkts, and thus, two ofst625 (ofst625 is -1 initially)
 
				if ( curr_ch2 != rx->channel2 )
				{

					new_slt = 1;
					// do swap
					tmp_slt = curr_slt;
					curr_slt = prev_slt;
					prev_slt = tmp_slt;

					curr_slt->slt_ch = rx->channel2;
					curr_slt->slt_rssi = 0;
					curr_slt->ofst625_1 = 0;
					curr_slt->ofst625_2 = 0;

					prev_ch2 = curr_ch2;
					prev_clkns2 = curr_clkns2;
					prev_cl	= curr_cl;

					curr_ch2 = rx->channel2;
					curr_clkns2 = rx->clk100ns2;
					curr_cl = rx->channel;

				}
			}

///////////////////////////////////////////////////////////////////////////////

//			if 1 == missing_hdr_flag 
// 			missing_hdr_flag = 0;
//			get the rest of the hdr from the new incoming full_buffer
// 			analyze_pkt_hdr ( local_full, i );
// 			we can do i jump here i = i + 35; --i; // because we have ++ i
// 			we got a pkt flag, got_pkt = 1;

			air_sync  = air_sync << 8;
			air_sync  = 0x00ffffffffffffff & ( air_sync | full_buf [ i ] );

			for ( shift = 0; shift < 8; shift++ )
			{

				bit_errs = 
				local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );

				if  ( bit_errs  <= max_ac_errs )
				{	
					// timestamp is related to sync word
					//byte = ( ii % 50);
					bits = ( ( ii % 50) * 8) - (spec_bits - shift);

					if (bits < 0)	
					// then the timestamp must be in the prev buf
					{	
						bits = 400 + bits ;
						if (ii < 50) // ii is in the first buf64
						{	
							rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * 0 ] );
							buf_tm = rx->clk100ns - 4000;
						}

						else 
						{
							rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * (d - 1)] );
							buf_tm = rx->clk100ns ;
						}
					}

					// else it is in this buf
					else 
					{
						rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * d] );
						buf_tm = rx->clk100ns ;
					}

					pkt_tm = buf_tm + (bits * 10);

					if (prv_pkt_tm > pkt_tm)
						slots = (3276799999 + pkt_tm - prv_pkt_tm)/6250.0 ; 

					else    
						slots = (pkt_tm - prv_pkt_tm)/6250.0 ; 

					prv_pkt_tm = pkt_tm;


					if (  curr_clkns2 < pkt_tm )
					{
						ofst625 = (pkt_tm - curr_clkns2);
						ch2 	= curr_ch2;
						cl	= prev_cl;

						if ( 0 == curr_slt->ofst625_1 )
							curr_slt->ofst625_1 = ofst625;
						else 
							curr_slt->ofst625_2 = ofst625;
					}

					else if ( ( prev_clkns2 < pkt_tm ) && ( pkt_tm < curr_clkns2 ) )
					{
						ofst625 = (pkt_tm - prev_clkns2);
						ch2	= prev_ch2;
						cl	= curr_cl;

						new_slt = 2;
						if ( 0 == prev_slt->ofst625_1 )
							prev_slt->ofst625_1 = ofst625;
						else 
							prev_slt->ofst625_2 = ofst625;

					}


				printf ("Ac4 = %d, cl=%u, ch2=%u, err=%d, p_time=%u, ofst625=%d, stls=%f\n", 
					bits, rx->channel, ch2, bit_errs, pkt_tm, ofst625, slots);


///////////////////////////////////////////////////////////////////////////////////////////////////////
					if ( 392 < ii ) // 399 - 7 = 392 // 7 bytes is the max required for the hdr
					{
					// missing_hdr_flag = 1;
					// get what is available from the hdr
					}

					else
					{
					// missing_hdr_flag = 0;
					// get the entire header and do analysis
					// analyze_pkt_hdr ( local_full, i );
					// we can do i jump here i = i + 35; --i; // because we have ++ i
					// we got a pkt flag, got_pkt = 1;
					}

				}
			}
//////////////////////////////////////////////////////////////
			if ( 0 < new_slt )
			{

				print_slt ( prev_slt );
				printf ("----%d\n", add_new_slt2 ( ShmPTR_A, prev_slt, new_slt ) );
				new_slt = 0;

				if ( ( 0 != prev_slt->ofst625_1) && (0 !=prev_slt->ofst625_2 ) )
				{
					speed_ctrl_slt.ofst625_1 = prev_slt->ofst625_1;
					speed_ctrl_slt.ofst625_2 = prev_slt->ofst625_2;
				}

			}

		++ i; ++ ii;
		}
///////////////////////////////////////////////////
//		these two must be outside the loop because we only need them if we need some info from prev but of 64 * 8
		rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * 7] );
		lst_buf_tm = rx->clk100ns;

		really_full = 0;
		fflush(stderr);
/////////////////////////////////////////////////
printf ("*************************\n");


// important note: don't talk to ubertooth in the above loop!!!
		ctrl_sig = uber_ctrl_sig5 ( &speed_ctrl_slt  );

		if ( 0 != ctrl_sig )
		{

		speed_ctrl_slt.ofst625_1 = 0;
		speed_ctrl_slt.ofst625_2 = 0;

		switch ( ctrl_sig )	{

		case SLOW_DOWN22:
			if ( 2 <= uber_std_speed){
			match_ctl [0] = SLOW_DOWN2;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
			}
			break;

		case STANDARD_SPEED:
			++ uber_std_speed;
			if ( 2 == uber_std_speed){
			match_ctl [0] = STANDARD_SPEED;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
			}
			break;

		}
		ctrl_sig = 0;
		}


//#ifdef ADPTV04
		if ( AFH_GT_FILLED2 == ShmPTR_A->AFH_status) 
		{
			printf ("afterwe got afh\n");
			ShmPTR_A->AFH_status = AFH_GT_EMPTY2;
			cmd_set_afh_map	(devh, ShmPTR_A->GT_afh);
		}

//#endif
		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


	}
	
out:

return 0;

}
///////////////////////////////////////////////////////////
int stream_rx_usb_ADPTV066 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_A, struct _piconet_info_ *pico_info)
{
//BUFFER_SIZE 102400
int 		r, i, ii=0, xfer_blocks, num_xfers, 
		ofst625 = 0, bits = 0, spec_bits = ( 8 * 8 ) + 4,
		bit_errs = 0, shift, b = 0, d = 0, curr_d, max_ac_errs = 5;

uint8_t 	rx_buf1[BUFFER_SIZE], 
		rx_buf2[BUFFER_SIZE], afh_map [10];

int8_t  	curr_rssi ;
uint8_t		byte =0, new_slt = 0, cl, curr_cl, prev_cl, ch2, prev_ch2, curr_ch2 ,
		ctrl_sig = 0, uber_std_speed =0, match_ctl [2];

uint32_t 	buf_tm = 0, pkt_tm = 0, prv_pkt_tm = 0, lst_buf_tm= 0 , prev_clkns2 , curr_clkns2;
uint64_t 	air_sync = 0 ;
double 		slots = 0;


struct usb_pkt_rx2 *rx;
/////////////////////////////////////////
struct _slt_buf slt_buf1, slt_buf2, speed_ctrl_slt, *prev_slt, *curr_slt, *tmp_slt;

prev_slt 	= &slt_buf1;
curr_slt	= &slt_buf2;
//////////////////////////////////////////
	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */

	DO_USB_SETTING;

	cmd_set_clock (devh, 0 + (u32) pico_info->TargetCLK   );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		i = 0 ; ii = 0; 
		while ( i < 512 )
		{

			b = i % 64;
			i =  ( (0 <= b ) && (b <=13) ) ? (i + 14): i;			
			d = ii / 50;
///////////////////////////////////////////////////////////////////////////////////
			if ( curr_d != d)
			{
				curr_d = d;
				rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * d] );

				if ( 0 == curr_slt->slt_rssi )
					curr_slt->slt_rssi = rx->rssi_max;

				// for each ch there one rssi taken at the second slt
				// for each ch we have two pkts, and thus, two ofst625 (ofst625 is -1 initially)
 
				if ( curr_ch2 != rx->channel2 )
				{

					new_slt = 1;
					// do swap
					tmp_slt = curr_slt;
					curr_slt = prev_slt;
					prev_slt = tmp_slt;

					curr_slt->slt_ch = rx->channel2;
					curr_slt->slt_rssi = 0;
					curr_slt->ofst625_1 = 0;
					curr_slt->ofst625_2 = 0;

					prev_ch2 = curr_ch2;
					prev_clkns2 = curr_clkns2;
					prev_cl	= curr_cl;

					curr_ch2 = rx->channel2;
					curr_clkns2 = rx->clk100ns2;
					curr_cl = rx->channel;

				}
			}

///////////////////////////////////////////////////////////////////////////////

//			if 1 == missing_hdr_flag 
// 			missing_hdr_flag = 0;
//			get the rest of the hdr from the new incoming full_buffer
// 			analyze_pkt_hdr ( local_full, i );
// 			we can do i jump here i = i + 35; --i; // because we have ++ i
// 			we got a pkt flag, got_pkt = 1;

			air_sync  = air_sync << 8;
			air_sync  = 0x00ffffffffffffff & ( air_sync | full_buf [ i ] );

			for ( shift = 0; shift < 8; shift++ )
			{

				bit_errs = 
				local_count_bits ( air_sync  ^ pico_info->air_order_syncword [ shift ]   );

				if  ( bit_errs  <= max_ac_errs )
				{	
					// timestamp is related to sync word
					byte = ( ii % 50);
					bits = ( ( ii % 50) * 8) - (spec_bits - shift);

					if (bits < 0)	
					// then the timestamp must be in the prev buf
					{	
						bits = 400 + bits ;
						if (ii < 50) // ii is in the first buf64
						{	
							rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * 0 ] );
							buf_tm = rx->clk100ns - 4000;
						}

						else 
						{
							rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * (d - 1)] );
							buf_tm = rx->clk100ns ;
						}
					}

					// else it is in this buf
					else 
					{
						rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * d] );
						buf_tm = rx->clk100ns ;
					}

					pkt_tm = buf_tm + (bits * 10);

					if (prv_pkt_tm > pkt_tm)
						slots = (3276799999 + pkt_tm - prv_pkt_tm)/6250.0 ; 

					else    
						slots = (pkt_tm - prv_pkt_tm)/6250.0 ; 

					prv_pkt_tm = pkt_tm;


					if (  curr_clkns2 < pkt_tm )
					{
						ofst625 = (pkt_tm - curr_clkns2);
						ch2 	= curr_ch2;
						cl	= prev_cl;

						if ( 0 == curr_slt->ofst625_1 )
							curr_slt->ofst625_1 = ofst625;
						else 
							curr_slt->ofst625_2 = ofst625;
					}

					else if ( ( prev_clkns2 < pkt_tm ) && ( pkt_tm < curr_clkns2 ) )
					{
						ofst625 = (pkt_tm - prev_clkns2);
						ch2	= prev_ch2;
						cl	= curr_cl;

						new_slt = 2;
						if ( 0 == prev_slt->ofst625_1 )
							prev_slt->ofst625_1 = ofst625;
						else 
							prev_slt->ofst625_2 = ofst625;

					}


				printf ("Ac4 = %d, cl=%u, ch2=%u, err=%d, p_time=%u, ofst625=%d, stls=%f\n", 
					bits, rx->channel, ch2, bit_errs, pkt_tm, ofst625, slots);


///////////////////////////////////////////////////////////////////////////////////////////////////////
					if ( 392 < ii ) // 399 - 7 = 392 // 7 bytes is the max required for the hdr
					{
					// missing_hdr_flag = 1;
					// get what is available from the hdr
					}

					else
					{
					// missing_hdr_flag = 0;
					// get the entire header and do analysis
					// analyze_pkt_hdr ( local_full, i );
					// we can do i jump here i = i + 35; --i; // because we have ++ i
					// we got a pkt flag, got_pkt = 1;
					}

				}
			}
//////////////////////////////////////////////////////////////
			if ( 0 < new_slt )
			{

				print_slt ( prev_slt );
				printf ("----%d\n", add_new_slt2 ( ShmPTR_A, prev_slt, new_slt ) );
				new_slt = 0;

				if ( ( 0 != prev_slt->ofst625_1) && (0 !=prev_slt->ofst625_2 ) )
				{
					speed_ctrl_slt.ofst625_1 = prev_slt->ofst625_1;
					speed_ctrl_slt.ofst625_2 = prev_slt->ofst625_2;
				}

			}

		++ i; ++ ii;
		}
///////////////////////////////////////////////////
//		these two must be outside the loop because we only need them if we need some info from prev but of 64 * 8
		rx = (struct usb_pkt_rx2 *)( &full_buf [ PKT_LEN * 7] );
		lst_buf_tm = rx->clk100ns;

		really_full = 0;
		fflush(stderr);
/////////////////////////////////////////////////
printf ("*************************\n");


// important note: don't talk to ubertooth in the above loop!!!
		ctrl_sig = uber_ctrl_sig5 ( &speed_ctrl_slt  );

		if ( 0 != ctrl_sig )
		{

		speed_ctrl_slt.ofst625_1 = 0;
		speed_ctrl_slt.ofst625_2 = 0;

		switch ( ctrl_sig )	{

		case SLOW_DOWN22:
			if ( 2 <= uber_std_speed){
			match_ctl [0] = SLOW_DOWN2;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
			}
			break;

		case STANDARD_SPEED:
			++ uber_std_speed;
			if ( 2 == uber_std_speed){
			match_ctl [0] = STANDARD_SPEED;
			cmd_do_something(devh, match_ctl, 1);
			printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
			}
			break;

		}
		ctrl_sig = 0;
		}


//#ifdef ADPTV04
		if ( AFH_GT_FILLED2 == ShmPTR_A->AFH_status) 
		{
			printf ("afterwe got afh\n");
			ShmPTR_A->AFH_status = AFH_GT_EMPTY2;
			cmd_set_afh_map	(devh, ShmPTR_A->GT_afh);
		}

//#endif
		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


	}
	
out:

return 0;

}
///////////////////////////////////////////////////////////
int stream_rx_usb_BASIC0 ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
	int r, i, ii=0, jj =0, k=0, buf_pkts = 0, npkts=0, xfer_blocks, num_xfers, round_slts=0, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE], match_ctl [2];
	uint8_t ctrl_sig = 0, uber_sig_sent = 0, uber_sig2=0, sig_duration = 0, uber_std_speed =0;
	uint8_t prev_ch = 0;
	int8_t prev_ptype = -1;

	struct timeval currtime;
	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;

	uint8_t rx_data_loc [ 8 * 1024 ];

	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_set_clock (devh, 0 + (u32) ShmPTR->TargetCLK );

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{
			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			cb_rx_BASIC (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
//			cb_rx_BASIC06 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			cb_rx_BASIC06 (  rx, pico_info, &b_info, rx_data_loc, i, PRNT_MODE_ALL );
			bank = (bank + 1) % NUM_BANKS;


//			if  (  1 == b_info.have_pkt ) 
			{	

				ii 					= npkts % PKT_BUF_SIZE;
				ShmPTR->basic_pkt_clk6_1	[ ii ] 	= b_info.clk6_1 ;
//				ShmPTR->basic_pkt_slts		[ ii ] 	= b_info.slts   ;
//				ShmPTR->basic_pkt_type		[ ii ] 	= b_info.ptype  ;
				ShmPTR->basic_pkt_625offset	[ ii ] 	= b_info.pkt_625ofst   ;
//				ShmPTR->basic_pkt_ptime		[ ii ]  = b_info.pkt_time;

				++ npkts;
				ShmPTR->basic_pkt_idx			= npkts;

			}


			if ( prev_ch != b_info.channel2 )
			{
				jj 					= buf_pkts % PKT_BUF_SIZE;
				ShmPTR->bufb_pkt_type		[ jj ]  = b_info.ptype  ;
				ShmPTR->bufb_pkt_ch		[ jj ]  = b_info.channel2  ;
				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;
//				ShmPTR->bufb_pkt_och		[ jj ] 	= b_info.o_ch ;
//				ShmPTR->bufb_pkt_ptime		[ jj ] 	= b_info.pkt_time ;

				++ buf_pkts ;
				ShmPTR->bufb_pkt_idx			= buf_pkts;
			}

			else if ( prev_ch ==  b_info.channel2 )
			{

				ShmPTR->bufb_pkt_rssi		[ jj ]  = b_info.rssi  ;

				if ( prev_ptype < b_info.ptype ) // collect longest pkt
//				if ( ShmPTR->buf_pkt_type [ jj ] <= b_info.ptype ) // collect longest pkt
				{
					ShmPTR->bufb_pkt_type 	[ jj ]	= b_info.ptype;
//					ShmPTR->bufb_pkt_ptime	[ jj ] 	= b_info.pkt_time ;
				}


			}

			prev_ch 	= b_info.channel2;
			prev_ptype	= b_info.ptype;
 
		}

		memcpy (  &rx_data_loc [ 0  ] , rx->data, 50 );

		really_full = 0;
		fflush(stderr);


		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


//NUM_BANKS = 10
// Check 1 for 


//		if ( 1 == clk_found)
//		if ( 1 )
		{

		ctrl_sig = uber_ctrl_sig (ShmPTR, BASIC_HPNG);

//		if (  STANDARD_SPEED == ShmPTR->basic_pkt_status ) 
		switch ( ctrl_sig )
		{


			case SLOW_DOWN2:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_DOWN2);
//					}
				break;

			case SLOW_DOWN21:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN21;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN21);
//					}
				break;

			case SLOW_DOWN22:
//					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
//					}
				break;

			case SLOW_DOWN23:
//					if ( ShmPTR->basic_pkt_status == STANDARD_SPEED && 0){
					match_ctl [0] = SLOW_DOWN23;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_DOWN23);
					uber_sig_sent = 1;
					printf ("reply********************************************************************=%d\n", SLOW_DOWN23);
//					}
				break;

			case STANDARD_SPEED:
					if ( 0 == uber_std_speed){
					match_ctl [0] = STANDARD_SPEED;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", STANDARD_SPEED);
					ShmPTR->basic_pkt_status = STANDARD_SPEED;
//					if ( STANDARD_SPEED == ShmPTR->adptv_pkt_status )
//						buf_pkts = 0;
					uber_std_speed = 1;
					}
				break;

			case SLOW_AND_STANDARD24:
					if ( 0 == uber_sig2){
					match_ctl [0] = SLOW_AND_STANDARD24;
					cmd_do_something(devh, match_ctl, 1);
					printf ("reply=%d\n", SLOW_AND_STANDARD24);
					uber_sig2 = 1;
					}
				break;


			default:

					if ( 2 == sig_duration)
					{	
						uber_sig_sent = 0;
						sig_duration = 0;
					}
				
					++ sig_duration ;
			}
		}

	}
	
out:

return 0;

}
////////////////////////////////////////////////////////////////////////////////////////////////
static void cb_rx_BASIC8( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, uint8_t * rx_data_in, uint8_t print_mode)
{

	int round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 , length = 18;
	uint8_t pkt_LT_ADD, pkt_clk6_1, pkt_printed = 0, hec, fec13_header3 [ 4 * 8 * 3], white_header3[18];
	int8_t pkt_type=-1; 
	float slots;

	uint32_t pkt_time=0, hdr_data2=0, hdr_data3 = 0, hdr_data0 = 0, clk100ns2=0 ;

	clk100ns2 = 0xffffffff & le32toh (rx->clk100ns2);

//	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33	(  rx_data_in , fec13_header3 );

		err_header3 = unfec13_local 	( &fec13_header3 [ b_info->shift + 4 ], white_header3, 18);

		hdr_data0   = 0x3ffff & air_to_host32 (white_header3, 18);

		for (clock = 0; clock < 64; clock++)
		{

			// unwhiten step
			hdr_data2 = hdr_data0 ^ a [clock];

			hec       = 0xff & (hdr_data2 >> 10);

			if (pico_info->UAP == (0xff & UAP_from_hec( (0x3ff & hdr_data2), (       hec)) ) )
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);

				if  ( 4 <= pkt_LT_ADD)
					pkt_clk6_1 ^=  63;


				break ; // added recently
			}
		}

/////////////////////////////////////////////////////////////
		pkt_time = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
//		round_slts    = round_slots(slots);

	if ( (uint32_t) (slots) < (uint32_t) (slots+0.3))
		round_slts = (uint32_t) (slots+1);
	else 
		round_slts = (uint32_t) (slots  );
////////////////////////////////
//		if ( 0 == clk_count )
//		{
//			clk_count = -1;
//			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
////			pkt_type   = 16;// just to show that we got a pkt
//
//		}

		if ( -1 == pkt_type )
		{
			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			hdr_data2 = hdr_data0 ^ a [pkt_clk6_1];
//			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);
		}
///////////////////////////////////////////////////
// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
//				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
//				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
//		b_info->o_ch		= rx->original_ch2 ;

	}


//	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->pkt_time	= pkt_time;
//	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;
	b_info->slts		= round_slts ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{

		printf("Nclk6_1=%02u ptyp=%02d, Ac3=%03d, shft=%d, C=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
			b_info->ac_offset_find3,
			b_info->shift,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
			pkt_time, 
			b_info->pkt_clk100ns2,
//rx->original_ch,
//rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf ("N, %u, %u, ptype=%d,    ch2=%u, ch=%02d, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
//			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 		= clk100ns2 ;
//	prev_o_ch		= rx->original_ch;


}

/////////////////////////////////////////////////////////////////////////////////
static void cb_rx_BASIC9( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, uint8_t * rx_data_in, int jump, uint8_t print_mode)
//static void cb_rx_BASIC6( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode)
{

//	char syms[BANK_LEN * NUM_BANKS], header[18], oheader[18];
	int i, kk, round_slts=0, clock, clk_count=0,  err_header3,  ac_num_elems3=0 ;
	uint8_t o_ch, pkt_LT_ADD, pkt_clk6_1 = 0, pkt_printed = 0, pkt_FLOW=0, pkt_ARQN=0, pkt_SEQN=0, c6 = 0, 
		fec13_header3 [ 4 * 8 * 3], white_header3[18], unwhite_header3[18];
	int8_t pkt_type=-1; 
	float slots;
	int count, index, length = 18;

	uint32_t pkt_time=0, clk100ns2=0, hdr_data2=0, hdr_data3 = 0, hdr_data0 = 0;
	uint8_t  hec, hec3;
//uint16_t hdr_data3;
//	uint8_t rx_data [ 100 ];

	if (15 > skip ) { skip++; goto out; }

	/* Sanity check */
	if (rx->channel > (BT_CHANNELS-1))
	{ printf ("ERROR!!!, %u\n", rx->channel); goto out;}

//	memcpy ( & rx_data [ 0  ], prev_pkt2.data, 50 );
//	memcpy ( & rx_data [ 50 ], rx->data, 50 );
//	memcpy ( prev_pkt2.data  , rx->data, 50 );


	/* Look for packets with specified LAP, if given. Otherwise
	 * search for any packet. */

	clk100ns2 = 0xffffffff & le32toh (rx->clk100ns2);


//	ac_num_elems  = find_known_lap2 (b_info, syms, pico_info->syncword, BANK_LEN, 5) ;
//	ac_num_elems3 = find_known_lap4 (b_info, pico_info, rx_data, BANK_LEN, 5) ;
/////////////////////////////////////////////////////
//int find_known_lap5 ( struct buf_info *b_info, struct _piconet_info_ *p_info, uint8_t *stream, int jump,  int max_ac_errors )
//{

	uint64_t  * p1 ;
	int byte = -1 , bit_errors, shift;

//	for (count = 0; count < 50; count++) 
	for (byte = jump; byte < 50; byte++) 
	{

		p1 		= (uint64_t *) & rx_data_in [ byte ];
		p1 [ 0 ] 	= 0xffffffffffffff00 & p1 [ 0 ];

		for ( shift = 0; shift < 8; shift++ )
		{
//			printf ( "%016"PRIx64 ", %016"PRIx64 " \n",  p1 [ 0 ], p_info->reversed1 [ shift ]   );
			bit_errors = count_bits ( p1 [ 0 ] ^ pico_info->reversed1 [ shift ]   );
			if  ( bit_errors <= max_ac_errors )
			{	
				b_info->ac_offset_find3 = (byte * 8) + shift;
				b_info->byte		= byte;
				b_info->shift		= shift;
				ac_num_elems3		= 1;
				goto hdr_found;
//				return 1;
			}
		}
	}

//	return 0;
//}

hdr_found:

///////////////////////////////////////////////////////
//	for (kk=0; kk < ac_num_elems ; kk++)
	for (kk=0; kk < ac_num_elems3; kk++)
	{

		unpack_symbols33		( &rx_data_in [ b_info->byte + 8 ], fec13_header3 );

		err_header3 = unfec13_local 	( fec13_header3 + b_info->shift + 4 , white_header3, 18);

		hdr_data0   = 0x3ffff & air_to_host32 (white_header3, 18);

		for (clock = 0; clock < 64; clock++)
		{

			// unwhiten step
			hdr_data2 = hdr_data0 ^ a [clock];

			hec       = 0xff & (hdr_data2 >> 10);

			if (pico_info->UAP == (0xff & UAP_from_hec( (0x3ff & hdr_data2), (       hec)) ) )
			{
				++ clk_count; 

				pkt_clk6_1 = clock; 
				pkt_LT_ADD = 0x7 &  hdr_data2 ;
				pkt_type   = 0xf & (hdr_data2 >> 3);

				break ; // added recently
			}
		}
/////////////////////////////////////////

		if  ( 4 <= pkt_LT_ADD)
			pkt_clk6_1 ^=  63;


		pkt_time  = le32toh(rx->clk100ns) + (b_info->ac_offset_find3 * 10 );

		if (0xffffffff == prev_pkt_time ) // this is for the first pkt only
		{	
//			fst_pkt_time  = pkt_time;
			prev_pkt_time = pkt_time;
			prev_clk6_1   = pkt_clk6_1;
			prev_clk100ns2 = clk100ns2 ;
		}


		if (prev_pkt_time > pkt_time)
			slots = (3276799999 + pkt_time - prev_pkt_time)/6250.0 ; 

		else    
			slots = (pkt_time - prev_pkt_time)/6250.0 ; 
//////////////////////////////
		round_slts    = round_slots(slots);

////////////////////////////////
//		if ( 16 == pkt_type )
		if ( -1 == pkt_type )
		{

			clk_count = -1;
			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
			hdr_data2 = hdr_data0 ^ a [pkt_clk6_1];
//			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//			hdr_data2 = air_to_host32 (unwhite_header3, 18);
//			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
//			hdr_data2 = air_to_host32 (oheader, 18);
			pkt_LT_ADD = 0x7 & hdr_data2 ;
			pkt_type   = 0xf & (hdr_data2 >> 3);

//			clk_count = -1;
//			pkt_clk6_1 = (prev_clk6_1 + round_slts) % 64;
//			unwhiten1 (white_header3, unwhite_header3, clock, 18, 0);
//			hdr_data2 = air_to_host32 (unwhite_header3, 18);
////			unwhiten1(header, oheader, pkt_clk6_1 , 18, 0);
////			hdr_data2 = air_to_host32 (oheader, 18);
//			pkt_LT_ADD = 0x7 & hdr_data2 ;
//			pkt_type   = 0xf & (hdr_data2 >> 3);
//			pkt_FLOW   = 0x1 & (hdr_data2 >> 7);
//			pkt_ARQN   = 0x1 & (hdr_data2 >> 8);
//			pkt_SEQN   = 0x1 & (hdr_data2 >> 9);

		}

// final step
		pkt_printed = 1;
		prev_pkt_time = pkt_time;
		prev_clk6_1   = pkt_clk6_1;

	}


out:

	if ( 1 == pkt_printed )
	{

		if ( pkt_time < clk100ns2)
			{
				b_info->pkt_625ofst 	= (pkt_time - prev_clk100ns2)/10; 
				b_info->channel2 	= rx->channel;
				b_info->o_ch		= rx->original_ch ;
			}
		else 
			{
				b_info->pkt_625ofst 	= (pkt_time - clk100ns2)/10; 
				b_info->channel2 	= rx->channel2;
				b_info->o_ch		= rx->original_ch2 ;
			}
	}
	else
	{
		b_info->channel2 	= rx->channel2;
		b_info->o_ch		= rx->original_ch2 ;

	}


	b_info->have_pkt 	= pkt_printed;
	b_info->ptype 		= pkt_type;
	b_info->clk6_1 		= pkt_clk6_1;
	b_info->slts 		= round_slts;
	b_info->pkt_time	= pkt_time;
	b_info->pkt_clk100ns2	= clk100ns2;
	b_info->channel		= rx->channel;
	b_info->rssi		= rx->rssi_max ;


	if ( 1 == pkt_printed && ( (PRNT_MODE_ALL == print_mode) || (PRNT_MODE_REC == print_mode)) )
	{
//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);


////		printf(" clk6_1=%02u ptyp=%02d, Ac3=%03d, C6=%u, CC=%d, LT_AD=%u, H=%03x, ch2=%u, ch=%u, o_ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
////		printf(" clk6_1=%02u ptyp=%02d, C6=%u, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",
//		printf("%02u, %02d, %u, %u, %6x, %u, %03d, %.03f\n",                
//			b_info->clk6_1,
//			b_info->ptype, 	
//			
////			0x3f & rx->status,
////			clk_count,
//			pkt_LT_ADD, 
////			b_info->channel2,
//			b_info->channel,
////			-54 + ((int8_t) b_info->rssi) ,
//			pico_info->LAP,
////			b_info->pkt_625ofst,
//			pkt_time, 
////			b_info->pkt_clk100ns2,
//			round_slts,
//			slots  );



		printf("9clk6_1=%02u ptyp=%02d, Ac3=%03d, CC=%d, LT_AD=%u, ch2=%u, ch=%u, %d, LAP=%6x, off625=%d, ptime=%u, ns2=%u, slts=%.03f\n",    
			b_info->clk6_1,
			b_info->ptype, 	
//			b_info->ac_offset,
			b_info->ac_offset_find3,
			clk_count,
			pkt_LT_ADD, 
			b_info->channel2,
			b_info->channel,
			-54 + ((int8_t) b_info->rssi) ,
			pico_info->LAP,
			b_info->pkt_625ofst,
			pkt_time, 
			b_info->pkt_clk100ns2,
//rx->original_ch,
//rx->original_ch2,
			slots  );


	}

	else if ( 0 == pkt_printed  && PRNT_MODE_ALL == print_mode )
	{

//		for (i = 9; i > -1; i--)
//			printf("%02x", afh_map_host[i]);

		printf ("9, %u, %u, ptype=%d,    ch2=%u, ch=%02d, o_ch=%u, %d\n",
			rx->clk100ns,
			b_info->pkt_clk100ns2,
			b_info->ptype,
			b_info->channel2,
			b_info->channel,
			b_info->o_ch,
			-54 + ((int8_t) b_info->rssi) );

	}



	prev_clk100ns2 	= clk100ns2 ;
	prev_o_ch	= rx->original_ch;


}

///////////////////////////////////////////////////////////////////////////////////
int stream_rx_usb_ONECH_B ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
	int r, i, ii = 0, k, xfer_blocks, num_xfers, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE] , buf_sent = 0;

	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;


	struct timeval currtime;


	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
//NUM_BANKS = 10
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_rx_syms   (devh, num_blocks);

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}

	gettimeofday(&currtime, NULL);	
	printf ("begin time=%ld, %ld\n", currtime.tv_sec, currtime.tv_usec);


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{

			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			cb_rx_BASIC (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
//			cb_rx_BASIC7 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
			bank = (bank + 1) % NUM_BANKS;

			if( ( 1 == b_info.have_pkt ) && ( 0 == buf_sent ) && ( READY_FOR_ONECH_PKTS == ShmPTR->TargetCLK_status ) )
			{	

				ShmPTR->OneCh_clk6_1     [ ii ] = b_info.clk6_1 ;
				ShmPTR->OneCh_slts 	 [ ii ] = b_info.slts;
				ShmPTR->OneCh_pkt_idx 		= ( ++ ii );

				b_info.have_pkt 		= 0;

				if ( 1 == ii )
					ShmPTR->OneCh_Fst_pkt_time	= b_info.pkt_time;	

			}



			if ( 1 == buf_sent )
				ShmPTR->OneCh_Lst_pkt_time	= prev_pkt_time;

		}

		really_full = 0;
		fflush(stderr);


// check for stop signals
		if (  ( 1 == stop_ubertooth ) || (TARGET_CLK_FOUND == ShmPTR->TargetCLK_status)  )
		{

			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;

			gettimeofday(&currtime, NULL);	
			printf ("end time=%ld, %ld\n", currtime.tv_sec, currtime.tv_usec);

			return 1;

		}


// Load rec pkts

		if ( ( 51 < ii ) && ( 0 == buf_sent ) )
		{

			buf_sent = 1;
			ShmPTR->OneCh_status = ONECH_BUF_FILLED;
			printf ("buf_sent_onech \n");
			printf ("sample of data in shared memory... %d %d %d %d %d %d %d %d\n",
	                ShmPTR->OneCh_slts [0], ShmPTR->OneCh_slts [1], 
	                ShmPTR->OneCh_slts [2], ShmPTR->OneCh_slts [3], ShmPTR->OneCh_slts [4], 
			ShmPTR->OneCh_slts [5], ShmPTR->OneCh_slts [6], ShmPTR->OneCh_pkt_idx ) ;

			continue ;
		}


	}
	
out:
	return 0;

}

/////////////////////////////////////////////////////////////////////////////////
int stream_rx_usb_ONECH ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
	int r, i, ii = 0, k, xfer_blocks, num_xfers, bank = 0;
	uint8_t rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE] , buf_sent = 0;

	struct usb_pkt_rx2 *rx;
	struct buf_info b_info;
	b_info.have_pkt = 0;


	struct timeval currtime;


	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */
//if  (512 > 102400)
//PKT_LEN       64
//NUM_BANKS = 10
	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;

	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;


	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);

	cmd_rx_syms   (devh, num_blocks);

	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1;	}

	gettimeofday(&currtime, NULL);	
	printf ("begin time=%ld, %ld\n", currtime.tv_sec, currtime.tv_usec);


	while ( 1 ) 
	{

		while (!really_full) { handle_events_wrapper(); }

		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{

			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			cb_rx_BASIC (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
//			cb_rx_BASIC42 (  rx, pico_info, &b_info, bank, PRNT_MODE_REC );
			bank = (bank + 1) % NUM_BANKS;

			if( ( 1 == b_info.have_pkt ) && ( 0 == buf_sent ) && ( READY_FOR_ONECH_PKTS == ShmPTR->TargetCLK_status ) )
			{	

				ShmPTR->OneCh_clk6_1     [ ii ] = b_info.clk6_1 ;
				ShmPTR->OneCh_slts 	 [ ii ] = b_info.slts;
				ShmPTR->OneCh_pkt_idx 		= ( ++ ii );

				b_info.have_pkt 		= 0;

				if ( 1 == ii )
					ShmPTR->OneCh_Fst_pkt_time	= b_info.pkt_time;	

			}



			if ( 1 == buf_sent )
				ShmPTR->OneCh_Lst_pkt_time	= prev_pkt_time;

		}

		really_full = 0;
		fflush(stderr);


// check for stop signals
		if (  ( 1 == stop_ubertooth ) || (TARGET_CLK_FOUND == ShmPTR->TargetCLK_status)  )
		{

			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;

			gettimeofday(&currtime, NULL);	
			printf ("end time=%ld, %ld\n", currtime.tv_sec, currtime.tv_usec);

			return 1;

		}


// Load rec pkts

		if ( ( 51 < ii ) && ( 0 == buf_sent ) )
		{

			buf_sent = 1;
			ShmPTR->OneCh_status = ONECH_BUF_FILLED;
			printf ("buf_sent_onech \n");
			printf ("sample of data in shared memory... %d %d %d %d %d %d %d %d\n",
	                ShmPTR->OneCh_slts [0], ShmPTR->OneCh_slts [1], 
	                ShmPTR->OneCh_slts [2], ShmPTR->OneCh_slts [3], ShmPTR->OneCh_slts [4], 
			ShmPTR->OneCh_slts [5], ShmPTR->OneCh_slts [6], ShmPTR->OneCh_pkt_idx ) ;

			continue ;
		}


	}
	
out:
	return 0;

}

//////////////////////////////////////////////////////////////////////////////////
static int perm5(int z, int p_high, int p_low)
{
	int i, tmp, output, z_bit[5], p[14];
	int index1[] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
	int index2[] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};

	/* bits of p_low and p_high are control signals */
	for (i = 0; i < 9; i++)
		p[i] = (p_low >> i) & 0x01;
	for (i = 0; i < 5; i++)
		p[i+9] = (p_high >> i) & 0x01;

	/* bit swapping will be easier with an array of bits */
	for (i = 0; i < 5; i++)
		z_bit[i] = (z >> i) & 0x01;

	/* butterfly operations */
	for (i = 13; i >= 0; i--) {
		/* swap bits according to index arrays if control signal tells us to */
		if (p[i]) {
			tmp = z_bit[index1[i]];
			z_bit[index1[i]] = z_bit[index2[i]];
			z_bit[index2[i]] = tmp;
		}
	}

	/* reconstruct output from rearranged bits */
	output = 0;
	for (i = 0; i < 5; i++)
		output += z_bit[i] << i;

	return(output);
}

//////////////////////////////////////////////////////////////
/* generate the complete hopping sequence */
static void gen_hops( struct _GT_SEQ_ *GT_SEQ )
{
	/* a, b, c, d, e, f, x, y1, y2 are variable names used in section 2.6 of the spec */
	/* b is already defined */
	/* e is already defined */
	int a, c, d, f, x;
	int h, i, j, k, c_flipped, perm_in, perm_out;

	/* sequence index = clock >> 1 */
	/* (hops only happen at every other clock value) */
	int index = 0;
	f = 0;

	/* nested loops for optimization (not recalculating every variable with every clock tick) */
	for (h = 0; h < 0x04; h++) { /* clock bits 26-27 */
		for (i = 0; i < 0x20; i++) { /* clock bits 21-25 */
			a = GT_SEQ->a1 ^ i;
			for (j = 0; j < 0x20; j++) { /* clock bits 16-20 */
				c = GT_SEQ->c1 ^ j;
				c_flipped = c ^ 0x1f;
				for (k = 0; k < 0x200; k++) { /* clock bits 7-15 */
					d = GT_SEQ->d1 ^ k;
					for (x = 0; x < 0x20; x++) { /* clock bits 2-6 */
						perm_in = ((x + a) % 32) ^ GT_SEQ->b;
						/* y1 (clock bit 1) = 0, y2 = 0 */
						perm_out = perm5(perm_in, c, d);
						GT_SEQ->GT_seq[index] = GT_SEQ->bank[(perm_out + GT_SEQ->e + f) % BT_CHANNELS];
						if (GT_SEQ->AFH_MODE) {
							GT_SEQ->GT_seq [ index + 1 ] = GT_SEQ->GT_seq [ index ];
						} else {
							/* y1 (clock bit 1) = 1, y2 = 32 */
							perm_out = perm5 (perm_in, c_flipped, d);
							GT_SEQ->GT_seq[index + 1] = GT_SEQ->bank[(perm_out + GT_SEQ->e + f + 32) % BT_CHANNELS];
						}
						index += 2;
					}
					f += 16;
				}
			}
		}
	}
}
////////////////////////////////////
static void address_precalc ( struct _GT_SEQ_ *GT_SEQ)
{
	int i;
	uint32_t address = GT_SEQ->address;
	/* populate frequency register bank*/
	for (i = 0; i < BT_CHANNELS; i++)
			GT_SEQ->bank[i] = ((i * 2) % BT_CHANNELS);
	/* actual frequency is 2402 + pn->bank[i] MHz */


	/* precalculate some of single_hop()/gen_hop()'s variables */
	GT_SEQ->a1 = (address >> 23) & 0x1f;
	GT_SEQ->b = (address >> 19) & 0x0f;
	GT_SEQ->c1 = ((address >> 4) & 0x10) +
		((address >> 3) & 0x08) +
		((address >> 2) & 0x04) +
		((address >> 1) & 0x02) +
		(address & 0x01);
	GT_SEQ->d1 = (address >> 10) & 0x1ff;
	GT_SEQ->e = ((address >> 7) & 0x40) +
		((address >> 6) & 0x20) +
		((address >> 5) & 0x10) +
		((address >> 4) & 0x08) +
		((address >> 3) & 0x04) +
		((address >> 2) & 0x02) +
		((address >> 1) & 0x01);
}
////////////////////////////////////
// use GT_seq to find out CLK candidates
static void init_candidates ( struct _GT_SEQ_ *GT_SEQ )
{
	int i, k=0; 
	uint8_t ch = GT_SEQ->listen_ch;
	/* populate frequency register bank*/

	for (i = 0; i < SEQUENCE_LENGTH ; i++){

		if (ch == GT_SEQ->GT_seq[ i ]){
			GT_SEQ->CLK_candinc [ k ] = i;
			k++;	  
		}
	}
	/* actual frequency is 2402 + pn->bank[i] MHz */
	printf ("\nnum_cand = %d\n", k );
	GT_SEQ->num_candinc  = k;
}

//////////////////////////////////////////////////////////////////////////////////
//static const char * const TYPE_NAMES[] = {
//	"NULL", "POLL", "FHS", "DM1", "DH1/2-DH1", "HV1", "HV2/2-EV3", "HV3/EV3/3-EV3",
//	"DV/3-DH1", "AUX1", "DM3/2-DH3", "DH3/3-DH3", "EV4/2-EV5", "EV5/3-EV5", "DM5/2-DH5", "DH5/3-DH5"

///////////////////////////////////////////////////////////////////////////////////
static uint32_t hamm_ds5_inc072 (const struct _GT_SEQ_ *GT_SEQ, struct ShMemory  *ShmPTR, const int l, const int trails)

{
//dts      = is a list of distances (# of slots) between consecutive pkts of the same class
// l       = is the length of CLK6_1
// CLK_candinc [j] = CLK candidates extracted from GT assuming ubertooth listens to ch=39
// num_candinc = # of CLK candidates
	int i,j, cand_hamm2, max_hamm2=0;
	uint32_t cand, dst_to_fst=0, Winner_cand=0, Winner_cand_idx_jj = 0;
	for (j = 0; j < GT_SEQ->num_candinc - l; j++ )
	{

		dst_to_fst=0; cand_hamm2=0; 

		// take one cand atime
		cand = GT_SEQ->CLK_candinc [j]; 

		// for each incoming candidate cand find the distance between cand and the list
		for (i=0 ; i < l; i++)
		{

			dst_to_fst = dst_to_fst + ShmPTR->OneCh_slts [ i + trails + 1 ];

			if ( LISTEN_CHANNEL == GT_SEQ->GT_seq [ ( cand + dst_to_fst ) % SEQUENCE_LENGTH  ] )
				{cand_hamm2++; }

		}


		if ( (l/4) <= cand_hamm2)  
		{

			if ( (63 & cand) == ShmPTR->OneCh_clk6_1 [ trails ]  )
			{
				if (max_hamm2 <= cand_hamm2)
				{
					max_hamm2 = cand_hamm2; 

					Winner_cand = cand ;
					Winner_cand_idx_jj = j ;

//					candd1 = cand ;
//					candd1_idx_jj = j ;
				}
				printf (       "hamm2 %d, %u, %u\n", cand_hamm2, cand, Winner_cand);
//				fprintf (fout, "%d, %u, %u\n", cand_hamm2, cand, candd1);
//				++ found_cand ;
			}

		}

	}

out:
	ShmPTR->wCand 		= Winner_cand;
	ShmPTR->wCand_idx_jj 	= Winner_cand_idx_jj;
	return 0;
}
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
static int read_Seq_File ( struct _GT_SEQ_ *GT_SEQ  )
{
	FILE * pFile;

	uint32_t address = GT_SEQ->address;
	int seq_length, num_candinc;
	char buf [1024];

	memset (buf,0,1024);
	sprintf ( buf, "%u_seq_length", address );
	pFile = fopen (buf, "r");
	if ( NULL == pFile) { printf ("Err open hop seq files..\n"); exit(0) ; }
	fscanf (pFile, "%d", &seq_length );
	fclose (pFile);
	GT_SEQ->seq_length = seq_length;

	memset (buf,0,1024);
	sprintf ( buf, "%u_n_cands", address );
	pFile = fopen (buf, "r");
	if ( NULL == pFile) { printf ("Err open hop seq files..\n"); exit(0) ; }
	fscanf (pFile, "%d", &num_candinc );
	fclose (pFile);
	GT_SEQ->num_candinc = num_candinc;

	memset (buf,0,1024);
	sprintf ( buf, "%u_hops", address );
	pFile = fopen (buf, "rb");
	if ( NULL == pFile) { printf ("Err open hop seq files..\n"); exit(0) ; }
	fread (GT_SEQ->GT_seq, GT_SEQ->seq_length, sizeof(uint8_t) , pFile);
	fclose (pFile);

	memset (buf,0,1024);
	sprintf ( buf, "%u_cands", address );
	pFile = fopen (buf, "rb");
	if ( NULL == pFile) { printf ("Err open hop seq files..\n"); exit(0) ; }
	fread (GT_SEQ->CLK_candinc, GT_SEQ->num_candinc, sizeof(uint32_t), pFile);
	fclose (pFile);


  return 0;
}
///////////////////////////////////////
static void write_Seq_File ( struct _GT_SEQ_ *GT_SEQ  )
{
	FILE * pFile;
	uint32_t address = GT_SEQ->address;

	char buf [1024];
	memset (buf,0,1024);
	sprintf ( buf, "%u_seq_length", address );
	if ( NULL == (pFile = fopen (buf, "w") ) )
	{
		printf ("Err write seq\n");	exit ( 0 );
	}

	fprintf (pFile, "%ld", GT_SEQ->seq_length );
	fclose (pFile);

	memset (buf,0,1024);
	sprintf ( buf, "%u_n_cands", address );
	if ( NULL == (pFile = fopen (buf, "w") ) )
	{
		printf ("Err write seq\n");	exit ( 0 );
	}

	fprintf (pFile, "%d", GT_SEQ->num_candinc );
	fclose (pFile);

	memset (buf,0,1024);
	sprintf ( buf, "%u_hops", address );
	if ( NULL == (pFile = fopen (buf, "wb") ) )
	{
		printf ("Err write seq\n"); exit ( 0 );
	}

	if (0 == fwrite (GT_SEQ->GT_seq , GT_SEQ->seq_length, sizeof(uint8_t) , pFile) )
	{
		printf ("Err write bin\n"); exit ( 0 );
	}

	fclose (pFile);

	memset (buf,0,1024);
	sprintf ( buf, "%u_cands", address );
	if ( NULL == (pFile = fopen (buf, "wb") ) )
	{
		printf ("Err write seq\n");
		exit ( 0 );
	}

	if (0 == fwrite (GT_SEQ->CLK_candinc , GT_SEQ->num_candinc, sizeof(uint32_t), pFile) )
	{
		printf ("Err write bin\n");	exit ( 0 );
	}

	fclose (pFile);

//  return 0;
}
/////////////////////////////////////////////////////////////
void init_GT_SEQ ( struct _GT_SEQ_ *GT_SEQ , uint8_t hasSeqFile)
{
	// We are working on AFH79
	uint32_t address = GT_SEQ->address;
	uint8_t listen_ch = GT_SEQ->listen_ch;

	GT_SEQ->GT_seq 		= (uint8_t  *) calloc(SEQUENCE_LENGTH, sizeof (uint8_t) );
	GT_SEQ->CLK_candinc 	= (uint32_t *) calloc(SEQUENCE_LENGTH/16, sizeof (uint32_t));
	
	if ( NULL ==  GT_SEQ->GT_seq)
	{
		printf ("Err allocate GT_seq\n");exit (0);
	}

	if ( NULL ==  GT_SEQ->CLK_candinc)
	{
		printf ("Err allocate GT_seq\n");exit (0);
	}

	GT_SEQ->seq_length = SEQUENCE_LENGTH;
	// Do precalculation
	address_precalc( GT_SEQ );

	if ( 0 == hasSeqFile )
	{
	//Generate the ground truth seque
		gen_hops( GT_SEQ );
	// Generate a list of CLK cand, specify a channel CHANNEL = 39
		init_candidates ( GT_SEQ );
	// write hops & cand to a file
		write_Seq_File ( GT_SEQ );
	}
	else 
	// read hops & cand from a file
	{
		read_Seq_File ( GT_SEQ );
	}



}


void deinit_GT_SEQ ( struct _GT_SEQ_ *GT_SEQ )
{
	free (GT_SEQ->GT_seq	  );
	free (GT_SEQ->CLK_candinc );
}
/////////////////////////////////////////////////////////////////
void Find_TargetCLK ( struct ShMemory  *ShmPTR, struct _GT_SEQ_ *GT_SEQ  )
{

	uint32_t Last_pkt_time ,  curr_uber_clk = 0;
	int n_pkts = 0, trails;
	struct timeval currtime;

	ShmPTR->TargetCLK_status 	= READY_FOR_ONECH_PKTS ; 

//	while ( ShmPTR->TargetCLK_status != BUF_READY_ONECH_PKTS )
	while ( ShmPTR->OneCh_pkt_idx < 51 )
		;

	gettimeofday(&currtime, NULL);	
	printf ("client get data. %ld, %ld\n", currtime.tv_sec, currtime.tv_usec);
	printf ("sample of data in shared memory... %d %d %d %d %d %d %d %d\n",
                ShmPTR->OneCh_slts [0], ShmPTR->OneCh_slts [1], 
                ShmPTR->OneCh_slts [2], ShmPTR->OneCh_slts [3], 
		ShmPTR->OneCh_slts [4], ShmPTR->OneCh_slts [5], 
		ShmPTR->OneCh_slts [6], ShmPTR->OneCh_pkt_idx ) ;


	Last_pkt_time 	= ShmPTR->OneCh_Lst_pkt_time;
	n_pkts = 50 ; 

//	gettimeofday(&currtime, NULL);	
//	printf ("tm before search. %ld, %ld\n", currtime.tv_sec, currtime.tv_usec);


	trails = 0 ;
//	while ( (0 == found_cand) && (trails < 3 ) )
	{

		hamm_ds5_inc072 ( GT_SEQ, ShmPTR, n_pkts - 1, trails ); 
		++ trails;
	}


//	gettimeofday(&currtime, NULL);	
//	printf ("tm After search. %ld, %ld\n", currtime.tv_sec, currtime.tv_usec);


	Last_pkt_time = ShmPTR->OneCh_Lst_pkt_time;
	while ( Last_pkt_time == ShmPTR->OneCh_Lst_pkt_time )
			;

	printf ("wCand=%u, lst=%u, fst=%u, clk_diff=%u\n", 
	ShmPTR->wCand ,  
	ShmPTR->OneCh_Lst_pkt_time , 
	ShmPTR->OneCh_Fst_pkt_time,
	(ShmPTR->OneCh_Lst_pkt_time - ShmPTR->OneCh_Fst_pkt_time)/6250 );

//	curr_uber_clk = candd1 + (u32) ( (ShmPTR->OneCh_Lst_pkt_time - ShmPTR->OneCh_Fst_pkt_time)/6250);
	curr_uber_clk = ShmPTR->wCand + (u32) ( (ShmPTR->OneCh_Lst_pkt_time - ShmPTR->OneCh_Fst_pkt_time)/6250);

	ShmPTR->TargetCLK 		= curr_uber_clk;
	ShmPTR->TargetCLK_status 	= TARGET_CLK_FOUND ;


}
//////////////////////////////////////////////////////
int stream_rx_usb_ADPTV(struct libusb_device_handle* devh1, struct ShMemory  *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks)
{
	int r, rr, ii=0, i, jj = 0, buf_pkts = 0, npkts=0, xfer_blocks, num_xfers, bank = 0, trails = 0, speed_up=0, slow_down=0, standard = 0, afh_counter = -1;
	uint8_t  rx_buf1[BUFFER_SIZE], rx_buf2[BUFFER_SIZE], match_ctl [2], ctrl_sig = 0, uber_sig_sent = 0, uber_sig2=0, sig_duration = 0, uber_std_speed=0;
	uint8_t afh_map [10];
	uint8_t prev_ch = 0;
	int8_t prev_ptype = -1;

	struct usb_pkt_rx2* rx;
	struct buf_info b_info;

	SHM_reset_GH_afh ( ShmPTR );

	/*
	 * A block is 64 bytes transferred over USB (includes 50 bytes of rx symbol
	 * payload).  A transfer consists of one or more blocks.  Consecutive
	 * blocks should be approximately 400 microseconds apart (timestamps about
	 * 4000 apart in units of 100 nanoseconds).
	 */

	if (devh1 == NULL) { printf ("Couldnot open devh1\n"); return 1; }

	if (xfer_size > BUFFER_SIZE)
		xfer_size = BUFFER_SIZE;
	xfer_blocks = xfer_size / PKT_LEN;
	xfer_size = xfer_blocks * PKT_LEN;
	num_xfers = num_blocks / xfer_blocks;
	num_blocks = num_xfers * xfer_blocks;


	empty_buf = &rx_buf1[0];
	full_buf = &rx_buf2[0];
	really_full = 0;
	rx_xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(rx_xfer, devh1, DATA_IN, empty_buf,
			xfer_size, cb_xfer, NULL, TIMEOUT);


	printf ("TargetCLK=%u\n", ShmPTR->TargetCLK);
	cmd_set_clock (devh1, 0 + (u32) ShmPTR->TargetCLK );


	r = libusb_submit_transfer(rx_xfer);
	if (r < 0) { fprintf(stderr, "rx_xfer submission: %d\n", r); return -1; }


	while ( 1 ) 
	{
		while (!really_full) { handle_events_wrapper(); }


		/* process each received block */
		for (i = 0; i < xfer_blocks; i++) 
		{

			rx = (struct usb_pkt_rx2 *)(full_buf + PKT_LEN * i);

//			cb_rx_BASIC4 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			cb_rx_BASIC6 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
//			cb_rx_BASIC7 (  rx, pico_info, &b_info, bank, PRNT_MODE_ALL );
			bank = (bank + 1) % NUM_BANKS;


//			if  (  1 == b_info.have_pkt ) 
			{	

				ii 					= npkts % PKT_BUF_SIZE;
				ShmPTR->adptv_pkt_clk6_1	[ ii ] 	= b_info.clk6_1 ;
				ShmPTR->adptv_pkt_slts		[ ii ] 	= b_info.slts   ;
				ShmPTR->adptv_pkt_type		[ ii ] 	= b_info.ptype  ;
				ShmPTR->adptv_pkt_625offset	[ ii ] 	= b_info.pkt_625ofst   ;
				ShmPTR->adptv_pkt_ptime		[ ii ]  = b_info.pkt_time;

				++ npkts;
				ShmPTR->adptv_pkt_idx			= npkts;

			}


			if ( prev_ch != b_info.channel2 )
			{
				jj 					= buf_pkts % PKT_BUF_SIZE;
				ShmPTR->bufa_pkt_type		[ jj ]  = b_info.ptype  ;
				ShmPTR->bufa_pkt_ch		[ jj ]  = b_info.channel2  ;
				ShmPTR->bufa_pkt_rssi		[ jj ]  = b_info.rssi  ;
				ShmPTR->bufa_pkt_och		[ jj ] 	= b_info.o_ch ;
				ShmPTR->bufa_pkt_ptime		[ ii ]  = b_info.pkt_time;
				ShmPTR->afh_remap		[ b_info.o_ch ] = b_info.channel;

				++ buf_pkts ;
				ShmPTR->bufa_pkt_idx			= buf_pkts;
			}

			else if ( prev_ch ==  b_info.channel2 )
			{

				ShmPTR->bufa_pkt_rssi		[ jj ]  = b_info.rssi  ;

				if ( prev_ptype < b_info.ptype ) // collect longest pkt
				{
					ShmPTR->bufa_pkt_type 		[ jj ]	= b_info.ptype;
					ShmPTR->bufa_pkt_ptime		[ ii ]  = b_info.pkt_time;
				}


			}

			prev_ch 	= b_info.channel2;
			prev_ptype	= b_info.ptype;



		}

		really_full = 0;
		fflush(stderr);


		if ( AFH_GT_FILLED == ShmPTR->GT_afh_BUF_status) 
		{

			SHM_get_GH_afh ( ShmPTR, afh_map );

			printf ("we got afh\n");

			cmd_set_afh_map	(devh1, afh_map);

		}

		if ( 1 == stop_ubertooth )
		{
			stop_ubertooth = 0;
			really_full = 0;
			usb_retry = 0;
			handle_events_wrapper();
			usb_retry = 1;
			return 1;
		}


/////// Speed CTL check
		ctrl_sig = uber_ctrl_sig (ShmPTR, ADPTV_HPNG);
//		if (  STANDARD_SPEED == ShmPTR->adptv_pkt_status ) 
		switch ( ctrl_sig )
		{

			case SLOW_DOWN2:
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh1, match_ctl, 1);
					printf ("reply=%d\n", SLOW_DOWN2);
				break;

			case SLOW_DOWN21:
					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN21;
					cmd_do_something(devh1, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN21);
					}
				break;

			case SLOW_DOWN22:
					if ( 1 == uber_std_speed){
					match_ctl [0] = SLOW_DOWN2;
					cmd_do_something(devh1, match_ctl, 1);
					printf ("reply********************************************************************=%d\n", SLOW_DOWN22);
					}
				break;


			case STANDARD_SPEED:
					if ( 0 == uber_std_speed){
					match_ctl [0] = STANDARD_SPEED;
					cmd_do_something(devh1, match_ctl, 1);
					afh_counter = 0;
					printf ("reply********************************************************************=%d\n", STANDARD_SPEED);

					ShmPTR->adptv_pkt_status = STANDARD_SPEED;

					uber_std_speed = 1;
					}
				break;

			case SLOW_AND_STANDARD24:
					if ( 0 == uber_sig2){
					match_ctl [0] = SLOW_AND_STANDARD24;
					cmd_do_something(devh1, match_ctl, 1);
					printf ("reply=%d\n", SLOW_AND_STANDARD24);
					uber_sig2 = 1;
					}
				break;


			default:

					if ( 2 == sig_duration)
					{	
						uber_sig_sent = 0;
						sig_duration = 0;
					}
				
					++ sig_duration ;
		}



	}
	
out:
	return 0;

}
////////////////////////////////////////////////////////////////////////////////////

