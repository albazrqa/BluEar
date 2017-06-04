/*
 * Copyright 2010 - 2013 Michael Ossmann, Dominic Spill, Will Code, Mike Ryan
 *
 * This file is part of Project Ubertooth.
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

#ifndef __UBERTOOTH_H__
#define __UBERTOOTH_H__

#include "ubertooth_control.h"
#include <btbb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>

//#include <mpalloc.h>

//#include <bluetooth_le_packet.h>
//#include "bluetooth_packet.c"

#include "SHM.h"
#include "SHM2.h"

/* Mark unused variables to avoid gcc/clang warnings */
#define UNUSED(x) (void)(x)

/* gnuplot output types
 * see https://github.com/dkogan/feedgnuplot for plotter */
#define GNUPLOT_NORMAL		1
#define GNUPLOT_3D		2


//#define MAX_PKTS_IN_FILE 30000
#define BT_CHANNELS 79
#define SEQUENCE_LENGTH 	134217728
#define LISTEN_CHANNEL 		39

/* RX USB packet parameters */
#define BUFFER_SIZE 1024
#define PKT_LEN       64
#define SYM_LEN       50
#define SYM_OFFSET    14
#define PKTS_PER_XFER 8
#define NUM_BANKS     10
#define XFER_LEN      (PKT_LEN * PKTS_PER_XFER)
#define BANK_LEN      (SYM_LEN * PKTS_PER_XFER)

// Speed CTRL
#define SLOW_DOWN2 		2
#define SLOW_DOWN21 		21
#define SLOW_DOWN22 		22
#define SLOW_DOWN23 		23
#define SLOW_AND_STANDARD24 	24
#define STANDARD_SPEED 		3


/// PKT LOAD and PRINT modes
#define PRNT_MODE_ALL 		90
#define PRNT_MODE_REC		91
#define BASIC_HPNG		100
#define ADPTV_HPNG		101
#define CHK_SIZE		4


#define LOCAL_BUF_SIZE 		100
//////////////////////////////////////////////////////////////
/* index into whitening data array */
static const uint8_t INDICES[] = {
99, 85, 17, 50, 102, 58, 108, 45, 92, 62, 
32, 118, 88, 11, 80, 2, 37, 69, 55, 8, 
20, 40, 74, 114, 15, 106, 30, 78, 53, 72, 
28, 26, 68, 7, 39, 113, 105, 77, 71, 25, 
84, 49, 57, 44, 61, 117, 10, 1, 123, 124, 
22, 125, 111, 23, 42, 126, 6, 112, 76, 24, 
48, 43, 116, 0};

/* whitening data */
static const uint8_t WHITENING_DATA[] = {1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1};
/*
1110001110110001010010111110101010000101101111001110010101100110000011011010111010001100100010000001001001101001111011100001111
*/

static const uint16_t fec23_gen_matrix[] = {
	0x2c01, 0x5802, 0x1c04, 0x3808, 0x7010,
	0x4c20, 0x3440, 0x6880, 0x7d00, 0x5600};
///////////////////////////////
struct _piconet_info_ {

	uint8_t 	UAP;
	uint64_t	reversed1 [ 8 ];
	uint64_t	air_order_syncword [ 8 ];
	uint32_t 	LAP;
	uint32_t 	address;
	uint32_t	TargetCLK;

	uint64_t 	syncword ;
	uint64_t 	reversed_syncword ;

} ;
///////////////////////////////////////////////////

struct buf_info {

	uint8_t		have_pkt;
	uint8_t		channel;
	uint8_t		channel2;
	uint8_t 	clk6_1;
//	uint8_t		ptype;
	int8_t		ptype;
	uint8_t		rssi;
	uint8_t		o_ch;
	uint8_t		bu[64 * 4];
	uint16_t	clkn;

	uint32_t 	pkt_time;
	uint32_t 	pkt_clk100ns2;
	uint32_t	buf_time;

	int 		slts ;
	int		pkt_625ofst;
	int		ac_offset;
	int		ac_offset_find3;  
	int		byte;
	int 		shift;
	int		err;
	int		ofst625 [ LOCAL_BUF_SIZE ];
	int		clk6	[ LOCAL_BUF_SIZE ];
	int		local_buf_idx;
//	uint8_t		raw_hdr [ 15 ];// at max it will be 12 bytes
	
};

////////////////////////////////////////////////////////////
struct _rx_info {

	int		hdr_bytes ; 
	uint8_t		have_pkt;
	uint8_t		channel;

	uint8_t 	clk6_1;
//	uint8_t		ptype;

	uint8_t		o_ch;
	uint16_t	clkn;

	uint32_t 	pkt_time;
	uint32_t 	pkt_clk100ns2;
	int 		slts ;
	int		pkt_625ofst;
	int		ac_offset;
	int		ac_offset_find3;  
	int		byte;
	int 		shift;
	int		ofst625 [ LOCAL_BUF_SIZE ];
	int		clk6	[ LOCAL_BUF_SIZE ];

	int8_t		ptype	[ LOCAL_BUF_SIZE ];
	uint8_t		rssi	[ LOCAL_BUF_SIZE ];
	uint8_t		channel2[ LOCAL_BUF_SIZE ];

	int		rx_buf_idx;
//	uint8_t		raw_hdr [ 15 ];// at max it will be 12 bytes
	
};

//////////////////////////////////////////////////////////////

struct _speed_ctrl_buf {

	int8_t		clk6	[ LOCAL_BUF_SIZE ];
	int		ofst625 [ LOCAL_BUF_SIZE ];
	int		local_buf_idx;

};
////////////////////////////////////////////////////////////

//typedef struct {
struct _GT_SEQ_ {
	/* these values for hop() can be precalculated in part (e.g. a1 is the
	 * precalculated part of a) */
	uint32_t a1, b, c1, d1, e;
	uint8_t AFH_MODE;
	uint32_t address;
	uint8_t listen_ch;

	// SEQUENCE_LENGTH = 134217728
	uint8_t *GT_seq ;
	uint8_t bank[BT_CHANNELS];

	//134217728/64=2097152
	uint32_t *CLK_candinc ;

	//number of candidates
	int num_candinc;
	long int seq_length;

} ;


////////////////////////////////////////////////////////////

static int  skip =0;
static uint32_t prev_clk100ns2 = 0xffffffff, prev_pkt_time = 0xffffffff;
static uint8_t prev_clk6_1 , prev_o_ch ;

uint32_t a []={ 
0x2f2c9,
0x24089,
0xabe9,
0x19a9,
0x1de59,
0x16c19,
0x38779,
0x33539,
0x16481,
0x1d6c1,
0x33da1,
0x38fe1,
0x24811,
0x2fa51,
0x1131,
0xa371,
0x139ed,
0x18bad,
0x360cd,
0x3d28d,
0x2157d,
0x2a73d,
0x4c5d,
0xfe1d,
0x2afa5,
0x21de5,
0xf685,
0x44c5,
0x18335,
0x13175,
0x3da15,
0x36855,
0x3175b,
0x3a51b,
0x14e7b,
0x1fc3b,
0x3bcb,
0x898b,
0x262eb,
0x2d0ab,
0x8113,
0x3353,
0x2d833,
0x26a73,
0x3ad83,
0x31fc3,
0x1f4a3,
0x146e3,
0xdc7f,
0x6e3f,
0x2855f,
0x2371f,
0x3f0ef,
0x342af,
0x1a9cf,
0x11b8f,
0x34a37,
0x3f877,
0x11317,
0x1a157,
0x66a7,
0xd4e7,
0x23f87,
0x28dc7
};

struct libusb_transfer *rx_xfer = NULL;
FILE *infile = NULL;
FILE *dumpfile = NULL;
usb_pkt_rx packets[NUM_BANKS];
char symbols[NUM_BANKS][BANK_LEN];
char Quiet = false;
u8 *empty_buf = NULL;
u8 *full_buf = NULL;
u8 really_full = 0;
int max_ac_errors = 2, global_jump = 0;
uint32_t systime;
u8 usb_retry = 1;
u8 stop_ubertooth = 0;
btbb_piconet *follow_pn = NULL; // currently following this piconet


struct usb_pkt_rx2 prev_pkt2;

enum board_ids {
	BOARD_ID_UBERTOOTH_ZERO = 0,
	BOARD_ID_UBERTOOTH_ONE  = 1,
	BOARD_ID_TC13BADGE      = 2
};

typedef void (*rx_callback)(void* args, usb_pkt_rx *rx, int bank);

struct libusb_device_handle* ubertooth_start(int ubertooth_device);


void ubertooth_stop(struct libusb_device_handle *devh);
int specan(struct libusb_device_handle* devh, int xfer_size, u16 num_blocks,
	u16 low_freq, u16 high_freq);
int do_specan(struct libusb_device_handle* devh, int xfer_size, u16 num_blocks,
	u16 low_freq, u16 high_freq, char gnuplot);
int cmd_ping(struct libusb_device_handle* devh);
int stream_rx_usb(struct libusb_device_handle* devh, int xfer_size,
	uint16_t num_blocks, rx_callback cb, void* cb_args);
int stream_rx_file(FILE* fp, uint16_t num_blocks, rx_callback cb, void* cb_args);
void rx_live(struct libusb_device_handle* devh, btbb_piconet* pn, int timeout);
void rx_file(FILE* fp, btbb_piconet* pn);
void rx_dump(struct libusb_device_handle* devh, int full);
void rx_btle(struct libusb_device_handle* devh);
void rx_btle_file(FILE* fp);
void cb_btle(void* args, usb_pkt_rx *rx, int bank);
static void cb_xfer(struct libusb_transfer *xfer);
static uint32_t air_to_host32(char *air_order, int bits);
static int count_bits(uint64_t n);
////////////////////////////////////////////////////////
void 	init_GT_SEQ ( struct _GT_SEQ_ *GT_SEQ , uint8_t hasSeqFile);
void 	deinit_GT_SEQ 	( struct _GT_SEQ_ *GT_SEQ );
void 	Find_TargetCLK 	( struct ShMemory  *ShmPTR, struct _GT_SEQ_ *GT_SEQ  );

static void 	cb_rx_BASIC6( struct usb_pkt_rx2 *rx, struct _piconet_info_ *pico_info, struct buf_info *b_info, int bank, uint8_t print_mode);
static int 	find_known_lap5 ( struct buf_info *b_info, struct _piconet_info_ *p_info, uint8_t *stream, int jump,  int max_ac_errors );
static int 	find_known_lap4 ( struct buf_info *b_info, struct _piconet_info_ *p_info, char *stream, int search_length, int max_ac_errors );
static void 	write_Seq_File ( struct _GT_SEQ_ *GT_SEQ  );
static int 	read_Seq_File ( struct _GT_SEQ_ *GT_SEQ  );
static void 	gen_hops( struct _GT_SEQ_ *GT_SEQ );
static void 	address_precalc ( struct _GT_SEQ_ *GT_SEQ);
static void 	init_candidates ( struct _GT_SEQ_ *GT_SEQ );
void 		init_pico_info ( struct _piconet_info_ *p_info );
int 		analyze_pkt_hdr ( struct _rx_info *rx_info, uint8_t *local_full, int i0, int hdr_bytes  );
static int 	local_count_bits (uint64_t n);

int stream_rx_usb_ADPTV	(struct libusb_device_handle* devh1, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks);
int stream_rx_usb_BASIC ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks);

int stream_rx_usb_BASIC05 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_B, struct _piconet_info_ *pico_info );
int stream_rx_usb_ADPTV05 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_A, struct _piconet_info_ *pico_info);
int stream_rx_usb_ADPTV06 ( struct libusb_device_handle* devh, struct ShMemory2 *ShmPTR_A, struct _piconet_info_ *pico_info);
int stream_rx_usb_ONECH   ( struct libusb_device_handle* devh, struct ShMemory *ShmPTR, struct _piconet_info_ *pico_info, int xfer_size, uint16_t num_blocks);
int cmd_set_bdaddr1(struct libusb_device_handle* devh, u32 address);

//uint8_t uber_ctrl_sig3 ( struct _ctrl_speed_data * speed_ctrl);
///////////////////////////////////////////////////////

#endif /* __UBERTOOTH_H__ */
