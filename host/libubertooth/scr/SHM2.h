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

#ifndef __SHM2_H__
#define __SHM2_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */
#include  <sys/ipc.h>
#include  <sys/shm.h>
#include  <inttypes.h>

// AFH GT BUFFER
#define  AFH_GT_FILLED2		242
#define  AFH_GT_EMPTY2		43

// SHARE MEM
#define CREATE_SHMEM2 		60
#define ATTACH_SHMEM2 		61

// BUFFERS
#define SHM2_PKT_BUF_SIZE 	300

///////////////////////////////////////////////////////////
struct _slt_buf{
	uint8_t slt_ch;
	int8_t	slt_rssi;
	int	ofst625_1;
	int	ofst625_2;

};

/////////////////////////////////////////////////
struct ShMemory2 {

// AFH GT BUFFER
	uint8_t		GT_afh_BUF_status;
	uint8_t 	AFH_status; 
	uint8_t 	GT_afh 			[ 10 ]; // from real BT

	uint8_t 	main_ch			[ SHM2_PKT_BUF_SIZE ];
	int8_t		ch_rssi			[ SHM2_PKT_BUF_SIZE ];
	int		ofst625_1 		[ SHM2_PKT_BUF_SIZE ];
	int		ofst625_2 		[ SHM2_PKT_BUF_SIZE ];

	int		ch_idx;

	int		read_indx;
	int		write_indx;

	int 		shmemIDD;

};

/////////////////////////////////////////////////////////////
//struct ShMemory2  * _Get_Shmem2_ (uint8_t mode);
struct ShMemory2  * _Get_Shmem2_ (uint8_t mode, char ID_letter);
uint8_t compare_n_cpy ( uint8_t * a, uint8_t * b, int L );
void 	detach_Shmem2 ( struct ShMemory2 * ShmPTR2 );
int	SHM2_get_idx ( struct ShMemory2  *ShmPTR2 ) ;
void SHM2_init_read_indx ( struct ShMemory2  *ShmPTR, int ofst_to_write );
void	SHM2_reset_GH_afh ( struct ShMemory2  *ShmPTR2 );
int SHM2_read_buf1 ( struct ShMemory2  *ShmPTR, struct _slt_buf *slt);
int SHM2_read_buf2 ( struct ShMemory2  *ShmPTR, struct _slt_buf *slt);
void 	print_slt ( struct _slt_buf *slt );
void	SHM2_read_buf ( struct ShMemory2  *ShmPTR2, struct _slt_buf *slt, int local_B_indx);

void	SHM2_set_GH_afh ( struct ShMemory2  *ShmPTR, uint8_t * afh_10 );
void	SHM2_get_GH_afh ( struct ShMemory2  *ShmPTR, uint8_t * afh_10 );

int 	add_new_slt2 ( struct ShMemory2 * ShmPTR2, struct _slt_buf *slt, uint8_t new_slt);

#endif /* __UBERTOOTH_H__ */
