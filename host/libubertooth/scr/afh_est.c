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

#include "afh_est.h"

///////////////////////////////////////////////////////////////
int8_t adjust_rssi ( int8_t rssi)
{
//	int8_t local_rssi;
//
//	// This is to restrict rssi between -100 and -20 dBm
//	if ( -20 < rssi  )
//		local_rssi = -20 ;
//	else if ( -100 > rssi)
//		local_rssi = -100 ;
//	     else
//		local_rssi = rssi ;
//
//	return -54 + ((-1 * local_rssi ) - 20);
printf ("Err adst\n");
exit (0);
return 0;
}
/////////////////////////////////////////
int8_t adjust_rssi2 ( int8_t rssi)
{
	int8_t loc_rssi = -1 * (rssi - 54);

	if (loc_rssi < 20)		loc_rssi = 20;
	else if (loc_rssi > 99)	loc_rssi = 99;

	return (loc_rssi -20);

}

//////////////////////////////////////

void _init_svm_files ( struct _svm_est_dat *svm_dat, struct _svm_files *f )
{

	strcpy ( f->train_docfile, 	"train_data");
	strcpy ( f->predict_docfile, 	"predict_data");
	strcpy ( f->modelfile, 		"svm_model");
	strcpy ( f->restartfile, 		"");  
	strcpy ( f->predictionsfile, 	"svm_predictions");

	memset (svm_dat->svm_label, 1, 79);
	memset (svm_dat->ch_state_svm, 1, 79);

}
//////////////////////////////////
void _reset_pkt_buffers ( struct _pkt_est_dat * pkt_dat )
{
	int i , j;
	for ( i = 0; i < 79; i++)
	{
		pkt_dat->n_visits 	[ i ]  = 0;
		pkt_dat->recvd_pkt	[ i ]  = 0;
	}
}
/////////////////////////////////
void _reset_rssi_buffers ( struct _svm_est_dat * svm_dat )
{
	int i , j;

	for ( i = 0; i < 79; i++)
	{
		for ( j = 0; j < dB_size; j ++ ) 
			svm_dat->ch_rssi [ i ][ j ] = 0;

	}

}

/////////////////////////////////////////////////////////////////////
void dat_analysis ( struct _channel_dat *ch_dat, struct _pkt_est_dat *pkt_dat, struct _svm_est_dat * svm_dat )
{
		

		if ( 0 < ch_dat->empty_slts  )
		{	
			-- ch_dat->empty_slts; 
			++ svm_dat->ch_rssi 		[ ch_dat->ch ][ adjust_rssi ( ch_dat->rssi ) ];
		}

		else 
		{
			++ pkt_dat->n_visits 		[ ch_dat->ch ];

			if ( -1 != ch_dat->ptype )  // check if it has a pkt
			{
				++ pkt_dat->recvd_pkt	[ ch_dat->ch ];
				++ ch_dat->total_n_pkts;

				switch ( ch_dat->ch )
				{
					case 15: case 14:	ch_dat->empty_slts = 2;
	
					case 16: case 10: case 11: case 12: case 13: 	ch_dat->empty_slts = 1;

					default: ch_dat->empty_slts = 0;
				}

			}
			else // -1 == B_ptype
				++ svm_dat->ch_rssi 		[ ch_dat->ch ][ adjust_rssi ( ch_dat->rssi ) ];
		}

}
//////////////////////////////////////////////////////////////////////
void print_ch_dat ( struct _channel_dat *ch_dat )
{

	printf (" ptyp=%02d, ch=%u, rssi=%d \n", 
			ch_dat->ptype,
			ch_dat->ch,
			adjust_rssi (-54 + ch_dat->rssi) 
			);

}
//////////////////////////////////////////////////////////////////////
void write_SVM_data_to_file ( struct _svm_est_dat * svm_dat, struct _svm_files *f, uint8_t data_type  )
{

	FILE * out_p = NULL;
	int i, j, num_samples = 1;

	if 	( TRAIN_DATA == data_type )
		out_p = fopen ( f->train_docfile, "w") ;


	else if	( PRDCT_DATA == data_type )
		out_p = fopen ( f->predict_docfile, "w") ;

	if ( NULL == out_p )
		{ printf ("Err SVM write to file\n"); exit (1); }

	for ( i = 0; i < 79; ++i) 
	{	

		if ( svm_dat->svm_label [ i ] )
			fprintf (out_p, "1 " );
		else 
			fprintf (out_p, "-1 " );


		for ( j = 0; j < dB_size; j ++) 
			num_samples += svm_dat->ch_rssi [ i ][ j ] ;

		for ( j = 0; j < dB_size; j ++) 
		{
			fprintf (out_p, "%d:%f ", j+1, (double) svm_dat->ch_rssi [ i ][ j ] / num_samples );
		}

			fprintf (out_p, "\n");

	}

fclose (out_p);

}
///////////////////////////////////////////////////////////////////////////////////////////
static double pp_test(int n_visit, int n_pkt, double avg_pkt_rate)
{
	double pr = 0.0;
	double coef = 1.0 ; 
	int i;

	for ( i = 0; i <= n_pkt; ++i) 
	{
		pr += coef*pow(avg_pkt_rate, i)*pow(1-avg_pkt_rate, n_visit-i);
		coef = (n_visit-i)*coef/(i+1);
	}

	return 2*pr;
}

//////////////////////////////////////////////////////////////////////////
int pkt_bsd_predict_func ( struct _pkt_est_dat * pkt_dat )
{
	int i, j, winner= -1, max_rate_indx = 0;
	double avg_pkt_rate_on_good = 0.0 , max_rate = 0.0, ch_estimation = 0.0;
	uint8_t collected_afh [ 10 ];
	// init loop
	for ( i = 0; i < 79 ; ++i )
	{
		pkt_dat->ch_est_pkt 	[ i ] = 0.0 ; 
		pkt_dat->pkt_label 	[ i ] = CH_UNKNOWN;

		if ( 0 == pkt_dat->n_visits [ i ] )
			pkt_dat->pkt_rate 	[ i ] = 0.0;
		else
			pkt_dat->pkt_rate 	[ i ] = (double) pkt_dat->recvd_pkt [ i ] / pkt_dat->n_visits [ i ];

		if (  max_rate <  pkt_dat->pkt_rate [ i ] )
		{	
			max_rate 	= pkt_dat->pkt_rate [ i ];
			max_rate_indx 	= i ;
		}

	}

	// just find the first max_rate
	pkt_dat->ch_est_pkt 		[ max_rate_indx ] = 1.0;
	pkt_dat->pkt_label 		[ max_rate_indx ] = CH_GOOD;
	/// find the 20 highest rates channels and the avrg rate
	for ( i = 0; i < 79 ; ++i )
	{
		winner = -1;
		for ( j = 0; j < 79 ; ++j ) 
		{

			if (  CH_UNKNOWN == pkt_dat->pkt_label    [ j ]  )
			{
			// then it must be the firts unknown ch
				if ( -1 == winner )
					winner = j ; 

				if (   pkt_dat->pkt_rate [ winner ] <=  pkt_dat->pkt_rate [ j ]   ) 
					winner = j ;
			}

		}

		// we get here only when we have less then 20 highest rates
		if ( i < 19  )
		{
			pkt_dat->ch_est_pkt 		[ winner ] = 1.0;
			pkt_dat->pkt_label 		[ winner ] = CH_GOOD;
		}

		// we get here when we have exactly 20 highest rates, and we find the avrg and break;
		else
		{
			break;
		}

	}

	/////////////////////////////////////////
	// we get here when we have exactly 20 highest rates, and we find the avrg and break;
	{
		for ( j = 0; j < 79 ; ++j ) 
		{
			if ( CH_GOOD == pkt_dat->pkt_label    [ j ]  )
				avg_pkt_rate_on_good += pkt_dat->pkt_rate [ j ];

		}

		avg_pkt_rate_on_good = 
			avg_pkt_rate_on_good / 20.0;
	}
	//////////////////////////////////////////
	///////// estimate the status of other channels rather than the 20 ones
	for ( i = 0; i < 79 ; ++i )
	{
		if ( CH_UNKNOWN == pkt_dat->pkt_label    [ i ] )
		{
			pkt_dat->ch_est_pkt [ i ] = 
			pp_test ( pkt_dat->n_visits [ i ], pkt_dat->recvd_pkt [ i ], avg_pkt_rate_on_good );

			pkt_dat->pkt_label    [ i ] =  pkt_dat->ch_est_pkt [ i ]  >= 0.0001 ? CH_GOOD : CH_BAD ;
		}
	}

out:

	for ( i = 0; i < 79; i++)
	{
		pkt_dat->n_visits 	[ i ]  = 0;
		pkt_dat->recvd_pkt	[ i ]  = 0;
	}
	return 0;

}
/////////////////////////////////////////////////////////////////////////////////////
void append_rssi_data_to_file ( struct _svm_est_dat * svm_dat, uint8_t *svm_labels_79, uint8_t *gt_labels_79  )
{
	FILE * out_p = NULL;
	int i, j, num_samples = 0;

	out_p = fopen ("rssi_before_predict", "a") ;

	if ( NULL == out_p )
		{ printf ("Err out_file\n"); exit (1); }

	for ( i = 0; i < 79; ++i) 
	{	

		fprintf (out_p, "%u, %u, ", svm_labels_79 [ i ], gt_labels_79 [ i ] );

		num_samples = 0;

		for ( j = 0; j < dB_size; j ++) 
			num_samples += svm_dat->ch_rssi [ i ][ j ] ;

		if ( 0 == num_samples )
			num_samples = 1;

		for ( j = 0; j < dB_size; j ++) 
		{
			fprintf (out_p, "%d:%f ", j+1, (double) svm_dat->ch_rssi [ i ][ j ] / num_samples );
		}

		fprintf (out_p, "\n");

	}

fclose (out_p);

}


//////////////////////////////////////////////////////////////////////////
//int main (int argc, char* argv[])
int learn_main ( struct _svm_est_dat * svm_dat, struct _svm_files *f  )
{  
  DOC **docs;  /* training examples */
  long totwords, totdoc,i, buffsize;
  double *target;
  double *alpha_in=NULL;
  KERNEL_CACHE *kernel_cache;
  LEARN_PARM learn_parm;
  KERNEL_PARM kernel_parm;
  MODEL *model=(MODEL *)my_malloc(sizeof(MODEL));

  verbosity		= 1;
  read_input_parameters_learn 	( &learn_parm, &kernel_parm);

  read_documents 		( f->train_docfile, &docs, &target, &totwords, &totdoc );

  buffsize = learn_parm.kernel_cache_size;

  if(kernel_parm.kernel_type == LINEAR) { /* don't need the cache */
    kernel_cache=NULL;
  }
  else {
    /* Always get a new kernel cache. It is not possible to use the
       same cache for two different training runs */
//    kernel_cache=kernel_cache_init ( totdoc, learn_parm.kernel_cache_size);


	kernel_cache			= (KERNEL_CACHE *)my_malloc(sizeof(KERNEL_CACHE));
	kernel_cache->index 		= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->occu 		= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->lru 		= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->invindex 		= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->active2totdoc 	= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->totdoc2active 	= (long *)my_malloc(sizeof(long)*totdoc);
	kernel_cache->buffer 		= (CFLOAT *)my_malloc((size_t)(buffsize)*1024*1024);

	kernel_cache->buffsize		=(long)(buffsize/sizeof(CFLOAT)*1024*1024);

	kernel_cache->max_elems		=(long)(kernel_cache->buffsize/totdoc);

	if ( kernel_cache->max_elems > totdoc )
	{
		kernel_cache->max_elems = totdoc;
	}

	if(verbosity>=2) 
	{
		printf(" Cache-size in rows = %ld\n", kernel_cache->max_elems);
		printf(" Kernel evals so far: %ld\n", kernel_cache_statistic);    
	}

	for(i=0;i<totdoc;i++) 
	{
		kernel_cache->index[i]		= -1;
		kernel_cache->lru[i]		= 0;
		kernel_cache->occu[i]		= 0;
		kernel_cache->invindex[i]	= -1;
		kernel_cache->active2totdoc[i]	= i;
		kernel_cache->totdoc2active[i]	= i;

	}

	kernel_cache->elems	= 0;   /* initialize cache */
	kernel_cache->activenum	= totdoc;
	kernel_cache->time	= 0;  


  }

  if(learn_parm.type == CLASSIFICATION) {
    svm_learn_classification(docs,target,totdoc,totwords,&learn_parm,
			     &kernel_parm,kernel_cache,model,alpha_in);
  }
  else if(learn_parm.type == REGRESSION) {
    svm_learn_regression(docs,target,totdoc,totwords,&learn_parm,
			 &kernel_parm,&kernel_cache,model);
  }
  else if(learn_parm.type == RANKING) {
    svm_learn_ranking(docs,target,totdoc,totwords,&learn_parm,
		      &kernel_parm,&kernel_cache,model);
  }
  else if(learn_parm.type == OPTIMIZATION) {
    svm_learn_optimization(docs,target,totdoc,totwords,&learn_parm,
			   &kernel_parm,kernel_cache,model,alpha_in);
  }

  if(kernel_cache) {
    /* Free the memory used for the cache. */
    kernel_cache_cleanup(kernel_cache);
  }

  /* Warning: The model contains references to the original data 'docs'.
     If you want to free the original data, and only keep the model, you 
     have to make a deep copy of 'model'. */
  /* deep_copy_of_model=copy_model(model); */
//  write_model (svm_dat->modelfile, model);
  write_model (f->modelfile, model);

  free(alpha_in);
  free_model(model,0);
  for ( i = 0; i < totdoc; i++) 
    free_example ( docs[i], 1);

  free(docs);
  free(target);

  return(0);
}

/*---------------------------------------------------------------------------*/

//void read_input_parameters_learn( char *docfile,char *modelfile, char *restartfile,long *verbosity, LEARN_PARM *learn_parm,KERNEL_PARM *kernel_parm)
void read_input_parameters_learn ( LEARN_PARM *learn_parm, KERNEL_PARM *kernel_parm)
{
  long i;
  char type[100];
  
  /* set default */
  strcpy (learn_parm->predfile, "trans_predictions");
  strcpy (learn_parm->alphafile, "");
//  (*verbosity)			= 1;
  learn_parm->biased_hyperplane		= 1;
  learn_parm->sharedslack		= 0;
  learn_parm->remove_inconsistent	= 0;
  learn_parm->skip_final_opt_check	= 0;
  learn_parm->svm_maxqpsize		= 10;
  learn_parm->svm_newvarsinqp		= 0;
  learn_parm->svm_iter_to_shrink	= -9999;
  learn_parm->maxiter			= 100000;
  learn_parm->kernel_cache_size		= 40;
  learn_parm->svm_c			= 0.0;
  learn_parm->eps			= 0.1;
  learn_parm->transduction_posratio	= -1.0;
  learn_parm->svm_costratio		= 1.0;
  learn_parm->svm_costratio_unlab	= 1.0;
  learn_parm->svm_unlabbound		= 1E-5;
  learn_parm->epsilon_crit		= 0.001;
  learn_parm->epsilon_a			= 1E-15;
  learn_parm->compute_loo		= 0;
  learn_parm->rho			= 1.0;
  learn_parm->xa_depth			= 0;
  kernel_parm->kernel_type		= 2; // 2: radial basis function exp(-gamma ||a-b||^2)\n");
  kernel_parm->poly_degree		= 3;
  kernel_parm->rbf_gamma		= 1.0;
  kernel_parm->coef_lin			= 1;
  kernel_parm->coef_const		= 1;
  strcpy(kernel_parm->custom,"empty");
  strcpy(type,"c");

//  for(i=1;(i<argc) && ((argv[i])[0] == '-');i++) {
//    switch ((argv[i])[1]) 
//      { 
//      case '?': //print_help(); 
//		exit(0);
//      case 'z': i++; strcpy(type,argv[i]); break;
//      case 'v': i++; (*verbosity)=atol(argv[i]); break;
//      case 'b': i++; learn_parm->biased_hyperplane=atol(argv[i]); break;
//      case 'i': i++; learn_parm->remove_inconsistent=atol(argv[i]); break;
//      case 'f': i++; learn_parm->skip_final_opt_check=!atol(argv[i]); break;
//      case 'q': i++; learn_parm->svm_maxqpsize=atol(argv[i]); break;
//      case 'n': i++; learn_parm->svm_newvarsinqp=atol(argv[i]); break;
//      case '#': i++; learn_parm->maxiter=atol(argv[i]); break;
//      case 'h': i++; learn_parm->svm_iter_to_shrink=atol(argv[i]); break;
//      case 'm': i++; learn_parm->kernel_cache_size=atol(argv[i]); break;
//      case 'c': i++; learn_parm->svm_c=atof(argv[i]); break;
//      case 'w': i++; learn_parm->eps=atof(argv[i]); break;
//      case 'p': i++; learn_parm->transduction_posratio=atof(argv[i]); break;
//      case 'j': i++; learn_parm->svm_costratio=atof(argv[i]); break;
//      case 'e': i++; learn_parm->epsilon_crit=atof(argv[i]); break;
//      case 'o': i++; learn_parm->rho=atof(argv[i]); break;
//      case 'k': i++; learn_parm->xa_depth=atol(argv[i]); break;
//      case 'x': i++; learn_parm->compute_loo=atol(argv[i]); break;
//      case 't': i++; kernel_parm->kernel_type=atol(argv[i]); break;
//      case 'd': i++; kernel_parm->poly_degree=atol(argv[i]); break;
//      case 'g': i++; kernel_parm->rbf_gamma=atof(argv[i]); break;
//      case 's': i++; kernel_parm->coef_lin=atof(argv[i]); break;
//      case 'r': i++; kernel_parm->coef_const=atof(argv[i]); break;
//      case 'u': i++; strcpy(kernel_parm->custom,argv[i]); break;
//      case 'l': i++; strcpy(learn_parm->predfile,argv[i]); break;
//      case 'a': i++; strcpy(learn_parm->alphafile,argv[i]); break;
//      case 'y': i++; strcpy(restartfile,argv[i]); break;
//      default: printf("\nUnrecognized option %s!\n\n",argv[i]);
////	       print_help();
//	       exit(0);
//      }
//  }
//  if(i>=argc) {
//    printf("\nNot enough input parameters!\n\n");
////    wait_any_key();
////    print_help();
//    exit(0);
//  }

//  strcpy (docfile, argv[i]);
//  strcpy (docfile, "train_data");

//  if( ( i + 1) < argc) 
//	{
//	    strcpy (modelfile, argv[i+1]);
//	}
//  strcpy (modelfile, "svm_model");

  if(learn_parm->svm_iter_to_shrink == -9999) 
  {
    if(kernel_parm->kernel_type == LINEAR) 
      learn_parm->svm_iter_to_shrink=2;
    else
      learn_parm->svm_iter_to_shrink=100;
  }

  if(strcmp(type,"c")==0) 
  {
    learn_parm->type=CLASSIFICATION;
  }
  else if(strcmp(type,"r")==0) 
  {
    learn_parm->type=REGRESSION;
  }
  else if(strcmp(type,"p")==0) 
  {
    learn_parm->type=RANKING;
  }
  else if(strcmp(type,"o")==0) 
  {
    learn_parm->type=OPTIMIZATION;
  }
  else if(strcmp(type,"s")==0) 
  {
    learn_parm->type=OPTIMIZATION;
    learn_parm->sharedslack=1;
  }
  else 
  {
    printf("\nUnknown type '%s': Valid types are 'c' (classification), 'r' regession, and 'p' preference ranking.\n",type);
//    wait_any_key();
//    print_help();
    exit(0);
  }    

  if((learn_parm->skip_final_opt_check) && (kernel_parm->kernel_type == LINEAR)) 
  {
    printf("\nIt does not make sense to skip the final optimality check for linear kernels.\n\n");
    learn_parm->skip_final_opt_check=0;
  }    

  if((learn_parm->skip_final_opt_check) && (learn_parm->remove_inconsistent)) 
  {
    printf("\nIt is necessary to do the final optimality check when removing inconsistent \nexamples.\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }    

  if((learn_parm->svm_maxqpsize<2)) 
  {
    printf("\nMaximum size of QP-subproblems not in valid range: %ld [2..]\n",learn_parm->svm_maxqpsize); 
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(( learn_parm->svm_maxqpsize < learn_parm->svm_newvarsinqp )) 
  {
    printf("\nMaximum size of QP-subproblems [%ld] must be larger than the number of\n",learn_parm->svm_maxqpsize); 
    printf("new variables [%ld] entering the working set in each iteration.\n",learn_parm->svm_newvarsinqp); 
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->svm_iter_to_shrink < 1 ) 
  {
    printf("\nMaximum number of iterations for shrinking not in valid range: %ld [1,..]\n",learn_parm->svm_iter_to_shrink);
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->svm_c < 0 ) 
  {
    printf("\nThe C parameter must be greater than zero!\n\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->transduction_posratio > 1 ) 
  {
    printf("\nThe fraction of unlabeled examples to classify as positives must\n");
    printf("be less than 1.0 !!!\n\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->svm_costratio <= 0 ) 
  {
    printf("\nThe COSTRATIO parameter must be greater than zero!\n\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->epsilon_crit <= 0 ) 
  {
    printf("\nThe epsilon parameter must be greater than zero!\n\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if(learn_parm->rho<0) 
  {
    printf("\nThe parameter rho for xi/alpha-estimates and leave-one-out pruning must\n");
    printf("be greater than zero (typically 1.0 or 2.0, see T. Joachims, Estimating the\n");
    printf("Generalization Performance of an SVM Efficiently, ICML, 2000.)!\n\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }

  if((learn_parm->xa_depth < 0) || (learn_parm->xa_depth > 100)) 
  {
    printf("\nThe parameter depth for ext. xi/alpha-estimates must be in [0..100] (zero\n");
    printf("for switching to the conventional xa/estimates described in T. Joachims,\n");
    printf("Estimating the Generalization Performance of an SVM Efficiently, ICML, 2000.)\n");
//    wait_any_key();
//    print_help();
    exit(0);
  }
}

////////////////////////////////////////
//int classify_main ( 	struct _svm_est_dat *svm_dat   )
int classify_main ( 	struct _svm_est_dat *svm_dat, struct _svm_files *f   )
{
  DOC *doc;   /* test example */
  WORD *words;
  long max_docs,max_words_doc,lld;
  long totdoc=0,queryid,slackid;
  long correct=0,incorrect=0,no_accuracy=0;
  long res_a=0,res_b=0,res_c=0,res_d=0,wnum,pred_format;
  long j, i , k = 0 ;
  double t1,runtime=0;
  double dist,doc_label,costfactor;
  char *line,*comment; 
  FILE *predfl,*docfl;
  MODEL *model; 


	verbosity	= 2;
	pred_format	= 1;
  nol_ll( f->predict_docfile, &max_docs, &max_words_doc, &lld); /* scan size of input file */
//  nol_ll( svm_dat->predict_docfile, &max_docs, &max_words_doc, &lld); /* scan size of input file */
//  nol_ll(            predict_docfile, &max_docs, &max_words_doc, &lld); /* scan size of input file */
  max_words_doc+=2;
  lld+=2;

  line 	= (char *) my_malloc(sizeof(char)*lld);
  words = (WORD *) my_malloc(sizeof(WORD)*(max_words_doc+10));

//  model	= read_model ( svm_dat->modelfile );
  model	= read_model ( f->modelfile );

  if(model->kernel_parm.kernel_type == 0) { /* linear kernel */
    /* compute weight vector */
    add_weight_vector_to_linear_model(model);
  }
  
  if(verbosity>=2) {
    printf("Classifying test examples.."); fflush(stdout);
  }

//  if ((docfl = fopen ( svm_dat->predict_docfile, "r")) == NULL)
//  { perror ( svm_dat->predict_docfile); exit (1); }
  if ((docfl = fopen ( f->predict_docfile, "r")) == NULL)
  { perror ( f->predict_docfile); exit (1); }

//  if ((predfl = fopen ( svm_dat->predictionsfile, "w")) == NULL)
//  { perror ( svm_dat->predictionsfile); exit (1); }

  if ((predfl = fopen ( f->predictionsfile, "w")) == NULL)
  { perror ( f->predictionsfile); exit (1); }

  while((!feof(docfl)) && fgets(line,(int)lld,docfl)) 
  {
    if(line[0] == '#') continue;  /* line contains comments */
    parse_document ( line, words, &doc_label, &queryid, &slackid, &costfactor, &wnum, max_words_doc, &comment);
    totdoc++;
    if(model->kernel_parm.kernel_type == 0) //{   /* linear kernel */
    {
      for(j=0;(words[j]).wnum != 0;j++)// {  /* Check if feature numbers   */
      {
	if((words[j]).wnum>model->totwords) /* are not larger than in     */
	  (words[j]).wnum=0;               /* model. Remove feature if   */
      }                                        /* necessary.                 */
      doc = create_example(-1,0,0,0.0,create_svector(words,comment,1.0));
      t1=get_runtime();
      dist=classify_example_linear(model,doc);
      runtime+=(get_runtime()-t1);
      free_example(doc,1);
    }

    else 
    {                             /* non-linear kernel */
      doc = create_example(-1,0,0,0.0,create_svector(words,comment,1.0));
      t1=get_runtime();
      dist=classify_example(model,doc);
      runtime+=(get_runtime()-t1);
      free_example(doc,1);
    }

	if( dist > 0 ) 
	{
		if ( doc_label > 0 ) 
		{
			correct++; 
			res_a++; 
		}
		else 
		{
			incorrect++;
			res_b++;
		}

	}
	else 
	{
		if( doc_label < 0 ) 
		{
			correct++; 
			res_d++;
		}
		else
		{
			incorrect++;
			res_c++; 
		}
	}

	if ( 1 == pred_format )
	{ /* output the value of decision function */
		fprintf(predfl,"a: %.8g\n",dist);
		if ( k < 79 )
		{
			svm_dat->ch_est_svm [ k ] = dist;
			++ k;
		}
		else
			printf ("Err SVM_predict size\n");
	    }

    if((int)(0.01+(doc_label*doc_label)) != 1) 
      { no_accuracy=1; } /* test data is not binary labeled */

    if(verbosity>=2) 
    {
      if(totdoc % 100 == 0) 
      {
	printf("%ld..",totdoc); fflush(stdout);
      }
    }
  }

  fclose(predfl);
  fclose(docfl);
  free(line);
  free(words);
  free_model(model,1);

  if(verbosity>=2) 
  {
    printf("done\n");

/*   Note by Gary Boone                     Date: 29 April 2000        */
/*      o Timing is inaccurate. The timer has 0.01 second resolution.  */
/*        Because classification of a single vector takes less than    */
/*        0.01 secs, the timer was underflowing.                       */
    printf("Runtime (without IO) in cpu-seconds: %.2f\n",
	   (float)(runtime/100.0));
    
  }

  if((!no_accuracy) && (verbosity>=1))
//  if(                   (verbosity>=1))  
  {
    printf("Accuracy on test set: %.2f%% (%ld correct, %ld incorrect, %ld total)\n",(float)(correct)*100.0/totdoc,correct,incorrect,totdoc);
    printf("Precision/recall on test set: %.2f%%/%.2f%%\n",(float)(res_a)*100.0/(res_a+res_b),(float)(res_a)*100.0/(res_a+res_c));
  }

//  _reset_rssi_buffers (  svm_dat  );
//	int i , j;

	for ( i = 0; i < 79; i++)
	{
		for ( j = 0; j < dB_size; j ++ ) 
			svm_dat->ch_rssi [ i ][ j ] = 0;

	}

  return(0);
}
//////////////////////////////////////////////////////////////////////

void print_help_learn()
{
//  printf("\nSVM-light %s: Support Vector Machine, learning module     %s\n",VERSION,VERSION_DATE);
  copyright_notice();
  printf("   usage: svm_learn [options] example_file model_file\n\n");
  printf("Arguments:\n");
  printf("         example_file-> file with training data\n");
  printf("         model_file  -> file to store learned decision rule in\n");

  printf("General options:\n");
  printf("         -?          -> this help\n");
  printf("         -v [0..3]   -> verbosity level (default 1)\n");
  printf("Learning options:\n");
  printf("         -z {c,r,p}  -> select between classification (c), regression (r),\n");
  printf("                        and preference ranking (p) (default classification)\n");
  printf("         -c float    -> C: trade-off between training error\n");
  printf("                        and margin (default [avg. x*x]^-1)\n");
  printf("         -w [0..]    -> epsilon width of tube for regression\n");
  printf("                        (default 0.1)\n");
  printf("         -j float    -> Cost: cost-factor, by which training errors on\n");
  printf("                        positive examples outweight errors on negative\n");
  printf("                        examples (default 1) (see [4])\n");
  printf("         -b [0,1]    -> use biased hyperplane (i.e. x*w+b>0) instead\n");
  printf("                        of unbiased hyperplane (i.e. x*w>0) (default 1)\n");
  printf("         -i [0,1]    -> remove inconsistent training examples\n");
  printf("                        and retrain (default 0)\n");
  printf("Performance estimation options:\n");
  printf("         -x [0,1]    -> compute leave-one-out estimates (default 0)\n");
  printf("                        (see [5])\n");
  printf("         -o ]0..2]   -> value of rho for XiAlpha-estimator and for pruning\n");
  printf("                        leave-one-out computation (default 1.0) (see [2])\n");
  printf("         -k [0..100] -> search depth for extended XiAlpha-estimator \n");
  printf("                        (default 0)\n");
  printf("Transduction options (see [3]):\n");
  printf("         -p [0..1]   -> fraction of unlabeled examples to be classified\n");
  printf("                        into the positive class (default is the ratio of\n");
  printf("                        positive and negative examples in the training data)\n");
  printf("Kernel options:\n");
  printf("         -t int      -> type of kernel function:\n");
  printf("                        0: linear (default)\n");
  printf("                        1: polynomial (s a*b+c)^d\n");
  printf("                        2: radial basis function exp(-gamma ||a-b||^2)\n");
  printf("                        3: sigmoid tanh(s a*b + c)\n");
  printf("                        4: user defined kernel from kernel.h\n");
  printf("         -d int      -> parameter d in polynomial kernel\n");
  printf("         -g float    -> parameter gamma in rbf kernel\n");
  printf("         -s float    -> parameter s in sigmoid/poly kernel\n");
  printf("         -r float    -> parameter c in sigmoid/poly kernel\n");
  printf("         -u string   -> parameter of user defined kernel\n");
  printf("Optimization options (see [1]):\n");
  printf("         -q [2..]    -> maximum size of QP-subproblems (default 10)\n");
  printf("         -n [2..q]   -> number of new variables entering the working set\n");
  printf("                        in each iteration (default n = q). Set n<q to prevent\n");
  printf("                        zig-zagging.\n");
  printf("         -m [5..]    -> size of cache for kernel evaluations in MB (default 40)\n");
  printf("                        The larger the faster...\n");
  printf("         -e float    -> eps: Allow that error for termination criterion\n");
  printf("                        [y [w*x+b] - 1] >= eps (default 0.001)\n");
  printf("         -y [0,1]    -> restart the optimization from alpha values in file\n");
  printf("                        specified by -a option. (default 0)\n");
  printf("         -h [5..]    -> number of iterations a variable needs to be\n"); 
  printf("                        optimal before considered for shrinking (default 100)\n");
  printf("         -f [0,1]    -> do final optimality check for variables removed\n");
  printf("                        by shrinking. Although this test is usually \n");
  printf("                        positive, there is no guarantee that the optimum\n");
  printf("                        was found if the test is omitted. (default 1)\n");
  printf("         -y string   -> if option is given, reads alphas from file with given\n");
  printf("                        and uses them as starting point. (default 'disabled')\n");
  printf("         -# int      -> terminate optimization, if no progress after this\n");
  printf("                        number of iterations. (default 100000)\n");
  printf("Output options:\n");
  printf("         -l string   -> file to write predicted labels of unlabeled\n");
  printf("                        examples into after transductive learning\n");
  printf("         -a string   -> write all alphas to this file after learning\n");
  printf("                        (in the same order as in the training set)\n");

}

//////////////////////////////
void collect_afh ( uint8_t * out_buf_10, uint8_t * afh_est_79)
{
	int i, reminder, result ;
	uint8_t byte = 0;

	for ( i = 0 ; i < 80 ; i ++ )
	{
		result 		= i / 8 ;
		reminder 	= i % 8 ;

		if ( 1 == afh_est_79 [ i ] )
		{
			switch ( reminder  )
			{
				case 0:
					byte = byte ^ 0x01;
					break ;
				case 1:
					byte = byte ^ 0x02;
					break ;
				case 2:
					byte = byte ^ 0x04;
					break ;
				case 3:
					byte = byte ^ 0x08;
					break ;												
				case 4:
					byte = byte ^ 0x10;
					break ;
				case 5:
					byte = byte ^ 0x20;
					break ;												
				case 6:
					byte = byte ^ 0x40;
					break ;
				case 7:
					byte = byte ^ 0x80;
					break ;												
			}

		}

		// we finished this byte
		if ( 7 == reminder  )
		{
			out_buf_10 [ result ] 	= byte;
			byte		= 0;
		}

	}
out_buf_10 [ 9 ] = out_buf_10 [ 9 ] & 0x7f;
}
////////////////////////////////////////
void local_unpack_symbols(uint8_t* buf, uint8_t * unpacked)
{
	int i, j, k = 0, L = 10;
	for (i = 0; i < L; i++) {
		/* output one byte for each received symbol (0x00 or 0x01) */
		for (j = 7; j > -1; j--) {
			unpacked[ k ] = 0x01 & (buf[i]  >> j );
			++ k ;
		}
	}
}



/////////////////////////////////////
// afh map here is of size 79 bytes (i.e. uncollected afh)
int un_collect_afh ( uint8_t * collected_afh_10, uint8_t * un_collected_afh_79)
{
//	int i, j, k = 0;
//
//	for ( i = 0; i < 10; i ++ )
//	{
//		for ( j = 0 ; j < 8; j ++ )
//		{
//			un_collected_afh_79 [ k ]= 0x01 & ( collected_afh_10 [ i ] >> j );
//			++ k ;
//			if ( 79 == k  )
//				goto out;
//
//		}
//
//	}
//
//out:
	return 0;
}
///////////////////////////////////////
// afh map here is of size 10 bytes (i.e. collected afh)
void print_afh_maps ( uint8_t *GT_afh, uint8_t * est_afh )//, int label1, int label2)
{
		int i;

		// 1 = GT
		printf ("1, ");		
		for ( i = 9 ; i > -1 ; i --)
			printf ("%02x", GT_afh [ i ] );

		printf ("\n");

		// 2 = EST
		printf ("2, ");		
		for ( i = 9 ; i > -1 ; i --)
			printf ("%02x", est_afh [ i ] );

		printf ("\n");


}
////////////////////////////////////////////
void print_afh_maps2 ( uint8_t *GT_afh, uint8_t * pkt_est_afh, uint8_t * svm_est_afh )//, int label1, int label2)
{
		int i;

		//////// 1 = GT
		printf ("1, ");		
		for ( i = 9 ; i > -1 ; i --)
			printf ("%02x", GT_afh [ i ] );

		printf ("\n");

		//////// 2 = EST pkt
		printf ("2, ");		
		for ( i = 9 ; i > -1 ; i --)
			printf ("%02x", pkt_est_afh [ i ] );

		printf ("\n");

		//////// 3 = EST svm
		printf ("3, ");		
		for ( i = 9 ; i > -1 ; i --)
			printf ("%02x", svm_est_afh [ i ] );

		printf ("\n");
}
