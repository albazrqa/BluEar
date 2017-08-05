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


#include "SHM2.h"
//////////////////////////////////////////////////////////////////////////////////////
//int8_t get_rssi ( struct ShMemory2 * ShmPTR2)
//{ return  ShmPTR2->ch_rssi [ (ShmPTR2->ch_idx) % SHM2_PKT_BUF_SIZE]; }
////////////////////////////////////////////////////////////////////////////////////////
//uint8_t get_ch ( struct ShMemory2 * ShmPTR2)
//{ return  ShmPTR2->main_ch [ (ShmPTR2->ch_idx) % SHM2_PKT_BUF_SIZE]; }
//////////////////////////////////////////////////////////////////////////////////////
void SHM2_init_read_indx ( struct ShMemory2  *ShmPTR, int ofst_to_write )
{
	ShmPTR->read_indx = ShmPTR->write_indx + ofst_to_write;

}
//////////////////////////////////////////////////////////////////////////////////////
int SHM2_read_buf1 ( struct ShMemory2  *ShmPTR, struct _slt_buf *slt)
{
	int B_indx = 0;

	if ( ShmPTR->read_indx < ShmPTR->write_indx)
	{

	 	B_indx = ShmPTR->read_indx % SHM2_PKT_BUF_SIZE;

		slt->slt_ch	= ShmPTR->main_ch   	[ B_indx  ];
		slt->slt_rssi	= ShmPTR->ch_rssi 	[ B_indx  ];
		slt->ofst625_1	= ShmPTR->ofst625_1 	[ B_indx  ];
		slt->ofst625_1	= ShmPTR->ofst625_1 	[ B_indx  ];

		B_indx 	= ShmPTR->read_indx;
		ShmPTR->read_indx = ( ++ B_indx );

	}

	return B_indx ;
}
//////////////////////////////////////////////////////////////////////////////
int SHM2_read_buf2 ( struct ShMemory2  *ShmPTR, struct _slt_buf *slt)
{
	int B_indx = 0;

	if ( ShmPTR->read_indx < (ShmPTR->write_indx-6))
	{

	 	B_indx = ShmPTR->read_indx % SHM2_PKT_BUF_SIZE;

		slt->slt_ch	= ShmPTR->main_ch   	[ B_indx  ];
		slt->slt_rssi	= ShmPTR->ch_rssi 	[ B_indx  ];
		slt->ofst625_1	= ShmPTR->ofst625_1 	[ B_indx  ];
		slt->ofst625_1	= ShmPTR->ofst625_1 	[ B_indx  ];

		B_indx 	= ShmPTR->read_indx;
		ShmPTR->read_indx = ( ++ B_indx );

	}

	return B_indx ;
}
//////////////////////////////////////////////////////////////////////////////////////

void SHM2_read_buf ( struct ShMemory2  *ShmPTR2, struct _slt_buf *slt, int local_B_indx)
{

	int B_indx 	= local_B_indx % SHM2_PKT_BUF_SIZE;

	slt->slt_ch	= ShmPTR2->main_ch   	[ B_indx  ];
	slt->slt_rssi	= ShmPTR2->ch_rssi 	[ B_indx  ];
	slt->ofst625_1	= ShmPTR2->ofst625_1 	[ B_indx  ];
	slt->ofst625_1	= ShmPTR2->ofst625_1 	[ B_indx  ];

}
///////////////////////////////////////////////////////////////////////////////////////
void SHM2_reset_GH_afh ( struct ShMemory2  *ShmPTR2 )
{
	memset ( ShmPTR2->GT_afh, 0xff, 10 );
	ShmPTR2->GT_afh_BUF_status 	= AFH_GT_EMPTY2;
}
////////////////////////////////////////////////////////////////
void SHM2_get_GH_afh ( struct ShMemory2  *ShmPTR_A, uint8_t * afh_10 )
{

	afh_10 [ 0 ] = ShmPTR_A->GT_afh [ 0 ] ;
	afh_10 [ 1 ] = ShmPTR_A->GT_afh [ 1 ] ;
	afh_10 [ 2 ] = ShmPTR_A->GT_afh [ 2 ] ;
	afh_10 [ 3 ] = ShmPTR_A->GT_afh [ 3 ] ;
	afh_10 [ 4 ] = ShmPTR_A->GT_afh [ 4 ] ;
	afh_10 [ 5 ] = ShmPTR_A->GT_afh [ 5 ] ;
	afh_10 [ 6 ] = ShmPTR_A->GT_afh [ 6 ] ;
	afh_10 [ 7 ] = ShmPTR_A->GT_afh [ 7 ] ;
	afh_10 [ 8 ] = ShmPTR_A->GT_afh [ 8 ] ;
	afh_10 [ 9 ] = ShmPTR_A->GT_afh [ 9 ] ;

//	ShmPTR_A->AFH_status 	= AFH_GT_EMPTY2;

}
////////////////////////////////////////////////////////////////
void SHM2_set_GH_afh ( struct ShMemory2  *ShmPTR, uint8_t * afh_10 )
{
	if ( 0 != compare_n_cpy ( ShmPTR->GT_afh, afh_10, 10 ) )
	{

		ShmPTR->AFH_status = AFH_GT_FILLED2 ;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////
uint8_t compare_n_cpy ( uint8_t * a, uint8_t * b, int L )
{
	int i; uint8_t res = 0;
	for (i = 0; i < L; ++i)
	{
		if ( a [ i ] != b [ i ] )
		{	
			a [ i ] = b [ i ];
			res = 1;
		}

	}

	return res;
//	if ( 0 != memcmp ( a, b, L ) )
//	{
//		memcpy ( a, b, L );
//		return 1;
//	}
//
//	else return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
int SHM2_get_idx ( struct ShMemory2  *ShmPTR2 ) 
{ 
	return ShmPTR2->ch_idx; 
}
////////////////////////////////////////////////////////////////////////////////////
void print_slt ( struct _slt_buf *slt )
{

	printf ("SHM ch2=%u, rssi=%d, ofs1=%d, ofs2=%d\n" , 
	slt->slt_ch,
	slt->slt_rssi-54,
	slt->ofst625_1,
	slt->ofst625_2
	);

}
///////////////////////////////////////////////////////////////////////////////////
int add_new_slt2 ( struct ShMemory2 * ShmPTR2, struct _slt_buf *slt, uint8_t new_slt)
{

	int loc_idx 	= ShmPTR2->write_indx ;
	int jj 		= loc_idx % SHM2_PKT_BUF_SIZE;
	// attach to an exist pkt
	if ( 2 == new_slt )
	{
		ShmPTR2->ofst625_1 [ jj ] = slt->ofst625_1;
		ShmPTR2->ofst625_2 [ jj ] = slt->ofst625_2;
	}

	else if ( 1 == new_slt )
	{ // add new slt
	ShmPTR2->main_ch   [ jj ] = slt->slt_ch ;
	ShmPTR2->ch_rssi   [ jj ] = slt->slt_rssi;
	ShmPTR2->ofst625_1 [ jj ] = slt->ofst625_1;
	ShmPTR2->ofst625_2 [ jj ] = slt->ofst625_2;

	 ++ loc_idx ;

	}

	return (ShmPTR2->write_indx = loc_idx) ;
}
//////////////////////////////////////////////////////////

struct ShMemory2  * _Get_Shmem2_ (uint8_t mode, char ID_letter)
{
	key_t          ShmKEY;
	int            ShmID;
	struct ShMemory2  *ShmPTR2;

//	ShmKEY = ftok(".", 'A');
	ShmKEY = ftok(".", ID_letter);

	if ( CREATE_SHMEM2 == mode)
		ShmID = shmget(ShmKEY, sizeof ( struct ShMemory2 ), IPC_CREAT | 0666);

	else if ( ATTACH_SHMEM2 == mode)
		ShmID = shmget(ShmKEY, sizeof ( struct ShMemory2 ), 0666);

	if (ShmID < 0) { printf("*** shmget error (%d) ***\n", mode); exit(1); }
	printf("Shared memory prepared at %d ...\n", mode);

	ShmPTR2 = (struct ShMemory2 *) shmat(ShmID, NULL, 0);

	if (!ShmPTR2 )  { printf("*** shmat error (%d) ***\n", mode); exit(1); }
	printf("Shared memory attached at %d ...\n", mode);

	if ( CREATE_SHMEM2 == mode)
		memset (ShmPTR2, 0, sizeof (struct ShMemory2));

	ShmPTR2->shmemIDD = ShmID;
	return ShmPTR2;
}
/////////////////////////////////////////////////////////////////////////////////
void detach_Shmem2 ( struct ShMemory2 * ShmPTR2 )
{
	int local_shmemIDD = ShmPTR2->shmemIDD;
	shmdt((void *) ShmPTR2);
	shmctl(local_shmemIDD, IPC_RMID, NULL);

}
/////////////////////////////////////////////////////////////////////////////////
