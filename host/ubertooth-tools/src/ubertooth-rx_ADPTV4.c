/*
 * Copyright 2010, 2011 Michael Ossmann
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

#include "ubertooth.h"
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>

//uint32_t address = 0x2a96ef25;
//uint32_t address = 0xdc065d23;
//uint32_t address = 0xdc06c0b3;
//uint32_t address = 0xdc0662ef;
//uint32_t address = 0x72c6653b;
//uint32_t address = 0x723397d3;
//uint32_t address = 0x72339685;
//uint32_t address = 0x72c61600;
//uint32_t address = 0xF889A175;
//uint32_t address = 0x72c66a0a;
//uint32_t address = 0x723397d3;
//uint32_t address = 0x01F3E10A;
//uint32_t address = 0xDC065D7F;
//uint32_t address = 0x72C62E7E;
//uint32_t address = 0x6AFE2C6F;
//uint32_t address = 0x72C66A2D;
//uint32_t address2 = 0xACE857F0;
//uint32_t address = 0xDC0662EF;
//#define address  0xDC065D58
//const uint32_t address = 0xDC065D58;
//uint32_t address = 0x72C669FD;
//uint32_t address = 0x72C613E2;
//uint32_t address = 0x7223B0D8;
//uint32_t address = 0x72C669E2;
//uint32_t address = 0x6AFE2C6F;
//uint32_t address = 0x72C66A1C;
//uint32_t address = 0x72C66A0E;
//uint32_t address = 0x6AFE334B;
//const uint32_t address = 0x6AFE2F40;
const uint32_t address = 0x6AFE2C6F;
//uint32_t address = 0x72C66A54;
//uint32_t address = 0xDD6C88A3;// Mouse
//uint32_t address = 0x72C61604;
#define LISTEN_ON_CH 39

#define ADPTV04

static void usage()
{
	printf ("No ubertooth device!!\n");
}

void cleanup(int sig)
{
	sig = sig;
	stop_ubertooth = 1;
}

int main(int argc, char *argv[])
{

	struct libusb_device_handle *devh = NULL;

	devh = ubertooth_start ( 1 );//ubertooth_device = 1

	if (devh == NULL) {
		usage();
		return 1;
		}

	cmd_set_bdaddr1( devh, address);

	/* Clean up on exit. */
	signal(SIGINT,cleanup);
	signal(SIGQUIT,cleanup);
	signal(SIGTERM,cleanup);

	struct _piconet_info_ pico_info;
	pico_info.address = address;
	init_pico_info ( &pico_info ) ;

	struct _GT_SEQ_ GT_SEQ;
	GT_SEQ.address = address;
	GT_SEQ.listen_ch = LISTEN_ON_CH;
//	init_GT_SEQ ( &GT_SEQ , 0);
	init_GT_SEQ ( &GT_SEQ , 1);

	struct ShMemory  *ShmPTR = _Get_Shmem_ (ATTACH_SHMEM, 'R');
//	assert(ShmPTR);
	struct ShMemory2 *ShmPTR_A = _Get_Shmem2_ (CREATE_SHMEM2, 'A');

	Find_TargetCLK ( ShmPTR, &GT_SEQ  );

	if ( TARGET_CLK_FOUND == ShmPTR->TargetCLK_status )
	{
		deinit_GT_SEQ ( &GT_SEQ );

		pico_info.TargetCLK = ShmPTR->TargetCLK;
//		stream_rx_usb_ADPTV05 ( devh, ShmPTR_A, &pico_info );
		stream_rx_usb_ADPTV06 ( devh, ShmPTR_A, &pico_info );
	}



	shmdt((void *) ShmPTR);
	detach_Shmem2 (ShmPTR_A);
	cmd_stop(devh);
	ubertooth_stop(devh);

	return 0;
}
