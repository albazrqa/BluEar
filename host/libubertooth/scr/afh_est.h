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

#ifndef __AFH_EST_H__
#define __AFH_EST_H__

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "SHM.h"

#ifdef __cplusplus
extern "C" {
#endif

# include "svm_common.h"
# include "svm_learn.h"

#ifdef __cplusplus
}
#endif


#define dB_size 	80
#define TRAIN_DATA	10
#define PRDCT_DATA	20

#define CH_BAD			0
#define CH_GOOD			1
#define CH_UNKNOWN		2


//////////////////////////////////////////////
struct _svm_files {
	char		train_docfile		[200];       /* file with training examples */
	char		predict_docfile		[200];       /* file with predict examples */
	char		modelfile		[200];       /* file for resulting classifier */
	char		restartfile		[200];       /* file with initial alphas */
	char		predictionsfile		[200];

};

struct _svm_est_dat {

//	char		train_docfile		[200];       /* file with training examples */
//	char		predict_docfile		[200];       /* file with predict examples */
//	char		modelfile		[200];       /* file for resulting classifier */
//	char		restartfile		[200];       /* file with initial alphas */
//	char		predictionsfile		[200];

	uint8_t		svm_label 		[ 79 ];

	uint8_t		ch_state_svm		[ 79 ];
	int		ch_rssi			[ 79 ] [ dB_size ]; // from -100 dBm to -20 dBm
	double		ch_est_svm		[ 79 ];
};
/////////////////////////////////////////////////////////////
struct _pkt_est_dat {

	int 		n_visits	[ 79 ];
	int		missd_pkt	[ 79 ];
	int		recvd_pkt	[ 79 ];
	uint8_t		ch_state_pkt	[ 79 ];
	uint8_t		pkt_label	[ 79 ];
	double		pkt_rate	[ 79 ];
	double		ch_est_pkt	[ 79 ];

};
/////////////////////////////////////////////////////////////
struct _network_dat {

	uint8_t		network_GT_afh [ 10 ];
	int		seq;

};
////////////////////////////////////////////////////////////
void 	collect_afh 		( uint8_t * out_buf_10, uint8_t * afh_est_79);
int	un_collect_afh		( uint8_t * collected_afh, uint8_t * un_collected_afh);
void 	local_unpack_symbols	( uint8_t* buf, uint8_t * unpacked);
//void	append_rssi_data_to_file ( struct _local_data * loc_dat, uint8_t *svm_labels_79,uint8_t *gt_labels_79  );
//void	append_rssi_data_to_file ( struct _local_data * loc_dat, , uint8_t *labels_79  );
//void 	write_SVM_data_to_file 	( struct _svm_est_dat * svm_dat, uint8_t * svm_label, uint8_t data_type  );
//void 	write_SVM_data_to_file 	( struct _svm_est_dat * svm_dat, uint8_t data_type  );
void 	write_SVM_data_to_file 	( struct _svm_est_dat * svm_dat, struct _svm_files *f, uint8_t data_type  );

int 	pkt_bsd_predict_func 	( struct _pkt_est_dat * pkt_dat );
void	dat_analysis 		( struct _channel_dat * ch_dat, struct _pkt_est_dat *pkt_dat, struct _svm_est_dat * svm_dat );
void	print_ch_dat 		( struct _channel_dat * ch_dat );

void 	_reset_rssi_buffers 	( struct _svm_est_dat * svm_dat );
void 	_reset_pkt_buffers	( struct _pkt_est_dat * pkt_dat );
void	_init_svm_files 	( struct _svm_est_dat * svm_dat, struct _svm_files *f );
int8_t	adjust_rssi 		( int8_t rssi);
int8_t	adjust_rssi2 		( int8_t rssi);

void	print_afh_maps 		( uint8_t * GT_afh, uint8_t * est_afh);//, int label1, int label2);
void	print_afh_maps2 	( uint8_t * GT_afh, uint8_t * pkt_est_afh, uint8_t * svm_est_afh );
void	print_help_learn 	( );

int 	classify_main 		( struct _svm_est_dat * svm_dat, struct _svm_files *f   );
int	learn_main 		( struct _svm_est_dat * svm_dat, struct _svm_files *f  );

void	read_input_parameters_learn	( LEARN_PARM *, KERNEL_PARM *);
void	read_input_parameters_classify	( long *, long *);
static double pp_test(int n_visit, int n_pkt, double avg_pkt_rate);
void 	_reset_pkt_buffers ( struct _pkt_est_dat * pkt_dat );
//////////////////////////////////////
//int 	do_svm_train_onetime ( struct ShMemory  *ShmPTR  );

/////////////////////////////////////////
#endif /* __AFH_EST_H__ */
