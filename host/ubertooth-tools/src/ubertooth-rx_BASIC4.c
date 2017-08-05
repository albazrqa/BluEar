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
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>

const uint32_t address = 0x6AFE2C6F;


#define LISTEN_ON_CH 39

static void usage()
{
	printf ("No ubertooth device\n");
}

void cleanup(int sig)
{
	sig = sig;
	stop_ubertooth = 1;

}

int main(int argc, char *argv[])
{


	struct libusb_device_handle *devh = NULL;

	devh = ubertooth_start ( 0 );//ubertooth_device = 0

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

	struct ShMemory  *ShmPTR = _Get_Shmem_ (CREATE_SHMEM, 'R');
//	assert(ShmPTR);

	struct ShMemory2 *ShmPTR_B = _Get_Shmem2_ (CREATE_SHMEM2, 'B');


	stream_rx_usb_ONECH ( devh, ShmPTR,  &pico_info, XFER_LEN, 0);

	if ( TARGET_CLK_FOUND == ShmPTR->TargetCLK_status )
	{
		pico_info.TargetCLK = ShmPTR->TargetCLK;
//		stream_rx_usb_BASIC05 ( devh, ShmPTR_B, &pico_info );
		stream_rx_usb_ADPTV06 ( devh, ShmPTR_B, &pico_info );
	}



out:
	detach_Shmem ( ShmPTR );
	detach_Shmem2 (ShmPTR_B);

	cmd_stop(devh);
	ubertooth_stop(devh);

	return 0;
}


