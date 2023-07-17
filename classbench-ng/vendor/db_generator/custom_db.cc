// File: custom_db.cc
// David E. Taylor
// Applied Research Laboratory
// Department of Computer Science and Engineering
// Washington University in Saint Louis
// det3@arl.wustl.edu
//
// Generates a synthetic database from seed file and input parameters

#include "stdinc.h"
#include "FilterList.h"
#include "ProtList.h"
#include "FlagList.h"
#include "ExtraList.h"
#include "PortList.h"
#include "PrefixList.h"
#include "dlist.h"
#include "sbintree.h"
#include "dbintree.h"
#include "redundant_filter_check.h"
#include "TupleBST.h"
#include "custom_db.h"
#include <network>
#include "ip_prefix.h"
#include "trie.h"
#include "filter_graph.h"

namespace ip = std::experimental::net::ip;


/*
 * Transforms a pruned source/destination trie into a set of edges from/to the
 * 's'/'t' node in the filter graph.
 * The given trie is recursively traversed. When the traversed node is a prefix
 * node, adding of the corresponding edge from/to the 's'/'t' node of the
 * filter graph is triggered. Weight of the added edge is set according to the
 * number of prefixes represented by the current prefix node.
 * CAUTION:
 *    * This function uses recursive calls!
 * @param node         A pointer to the current trie node.
 * @param src_trie     The trie node referenced by parameter node belongs to
 *                     the source trie (TRUE) or the destination trie (FALSE).
 * @param prefix_str   The prefix represented by the current node encoded as a
 *                     string of bit values.
 * @param graph        A pointer to the filter graph object.
 */
void trie_to_graph(const trie_node* node, bool src_trie, string prefix_str, Filter_graph* graph) {
   if (node != NULL) { // non-empty subtree
      int prefix_count = node->prefixes;
      if (prefix_count > 0) { // prefix node
         // add current prefix to the filter graph, either as "s_prefix" or as "t_prefix"
         IP_prefix prefix(prefix_str, true);
         if (src_trie) {
            graph->add_s_prefix(prefix, prefix_count);
         } else {
            graph->add_t_prefix(prefix, prefix_count);
         }
      }
      // call this function on both zero and one subtrees
      trie_to_graph(node->zero, src_trie, prefix_str + "0", graph);
      trie_to_graph(node->one, src_trie, prefix_str + "1", graph);
   } else { // empty subtree
      return;
   }
} // end trie_to_graph()


int custom_db_gen(int num_filters, FilterList* filters, FILE* fp_in, int smoothness, float addr_scope, float port_scope, int branch){

  // generate 100 times more filters (because of successive trie pruning)
  int temp_num_filters = num_filters * 100;

  printf("Initializing data structures...\n");
  // Read in scale
  int scale = read_scale(fp_in);
  // printf("scale = %d\n",scale);
  float scale_factor = (float)temp_num_filters/(float)scale;
  // printf("scale_factor = %.4f\n",scale);

  // Read protocol parameters, initialize data structure
  ProtList *protL = new ProtList();
  protL->read(fp_in);
  // protL->print(stdout);
  
  // Read flags distribution
  FlagList *flagL = new FlagList();
  flagL->read(fp_in);
  // flagL->print(stdout);

  // Read extra field distribution
  ExtraList *extraL = new ExtraList(protL->size());
  extraL->read(fp_in,scale_factor);
  // extraL->print(stdout);

  // Read port distributions, initialize four lists
  // Source ports, Arbitrary Ranges
  PortList *sparL = new PortList();
  (*sparL).read(0,fp_in);
  //(*sparL).print(stdout);

  // Source ports, Exact Ports
  PortList *spemL = new PortList();
  (*spemL).read(1,fp_in);
  //(*spemL).print(stdout);

  // Destination ports, Arbitrary Ranges
  PortList *dparL = new PortList();
  (*dparL).read(2,fp_in);
  //(*dparL).print(stdout);

  // Destination ports, Exact Ports
  PortList *dpemL = new PortList();
  (*dpemL).read(3,fp_in);
  //(*dpemL).print(stdout);

  // Read prefix length distributions, initialize
  PrefixList *prefixL = new PrefixList();
  prefixL->read(fp_in);
  prefixL->smooth(smoothness);
  // for(int i = 0; i < 25; i++) prefixL->print(i,stdout);

  printf(" \tdone\n");

  // Random number
  double p,pt,ps;

  // Temporary filter
  // struct filter temp_filter;
  struct filter *temp_filters = new struct filter[temp_num_filters+1];
  for (int i = 0; i < temp_num_filters+1; i++) {
    temp_filters[i].num_ext_field = 0;
  }
  dlist *Flist = new dlist;
  struct range temp_range;
  struct ppair temp_ppair;
  int port_type;

  printf("Creating application specifications...\n");
  
  // For all filters:
  for (int i = 1; i <= temp_num_filters; i++){
    // Select a protocol via random number
    p = drand48();
    temp_filters[i].prot_num = protL->choose_prot((float)p);
    // printf("prot_num = %d\n",temp_filters[i].prot_num);

    // Select flag specification
    p = drand48();
    flagL->choose((float)p,temp_filters[i].prot_num,&(temp_filters[i].flags),&(temp_filters[i].flags_mask));

    // Select extra fields
    temp_filters[i].num_ext_field = extraL->size();
    if (temp_filters[i].num_ext_field > 0) {
      temp_filters[i].ext_field = new int[temp_filters[i].num_ext_field];
      for (int j = 0; j < temp_filters[i].num_ext_field; j++) temp_filters[i].ext_field[j] = 0;
      extraL->choose(temp_filters[i].prot_num,temp_filters[i].ext_field);
      // printf("temp_filters[i].ext_field[0] = %d\n",temp_filters[i].ext_field[0]);
    }

    // Select a port range pair type from protocol distribution via random number
    // p = drand48();
    p = random_scope(port_scope);
    port_type = protL->choose_ports((float)p,temp_filters[i].prot_num);
    // printf("p = %f, temp_filters[%d].prot_num = %d, port_type = %d\n",(float)p,i,temp_filters[i].prot_num,port_type);

    // Select port range values based on type and distributions
    select_ports(port_type,&temp_filters[i],sparL,spemL,dparL,dpemL);
    // printf("sp [%d:%d]\tdp [%d:%d]\n",temp_filters[i].sp[0],temp_filters[i].sp[1],temp_filters[i].dp[0],temp_filters[i].dp[1]);

    // Select total prefix length from distribution associated with port range type
    // Use pseudo-random number generator
    pt = random_scope(addr_scope);
    // printf("random_scope done\n");

    // Select source/destination prefix length from source length distribution
    // Use random number
    ps = drand48();
    // printf("ps = %.4f, pt = %.4f, prot_type = %d\n",ps,pt,port_type);
    temp_ppair = prefixL->choose_prefix(port_type,(float)ps,(float)pt);
 
    // printf("temp_ppair.slen = %d, temp_ppair.dlen = %d\n",temp_ppair.slen,temp_ppair.dlen);
    // Assign prefix lengths to filter
    temp_filters[i].sa_len = temp_ppair.slen;
    temp_filters[i].da_len = temp_ppair.dlen;

    // Add temp_filter to temp_filters
    // temp_filters[i] = temp_filter;

    // Add i to list of filters
    *Flist&=i;
  }
  printf(" \tdone\n");
  // Free up memory
  delete(protL);
  delete(flagL);
  delete(extraL);
  delete(sparL);
  delete(spemL);
  delete(dparL);
  delete(dpemL);
  delete(prefixL);

  /*
  printf("Creating Stree1\n");
  sbintree *Stree1 = new sbintree();
  printf("Creating Stree2\n");
  sbintree *Stree2 = new sbintree();
  printf("Creating dlist\n");
  dlist* foo = new dlist;
  printf("Deleting Stree1\n");
  delete(Stree1);
  printf("Deleting Stree2\n");
  delete(Stree2);
  printf("Deleting dlist\n");
  delete(foo);
  */
  
  // Construct addresses
  // Read in skew distributions from parameter file 
  // or generate skew distributions according to input time constant
  printf("Creating source addresses...\n");
  sbintree *Stree = new sbintree();
  // Read source address nesting
  (*Stree).read_nest(fp_in);
  // Read source address skew
  (*Stree).read_skew(fp_in);
  // (*Stree).print_skew(stdout);
  if (branch == 1 && scale_factor > 1){
    (*Stree).scale_skew(scale_factor);
    // (*Stree).print_skew(stdout);
  }
  // printf("Flist = "); (*Flist).print(stdout); printf("\n");  
  (*Stree).build_tree(Flist,temp_filters);
  /*
  printf("Flist = "); (*Flist).print(stdout); printf("\n");
  for (int i = 1; i <= temp_num_filters; i++)
    printf("filter[%d].sa = %u/%d\n",i,temp_filters[i].sa,temp_filters[i].sa_len);
  */
  printf(" \tdone\n");

  printf("Creating destination addresses...\n");
  dbintree *Dtree = new dbintree();
  // Read destination address nesting
  (*Dtree).read_nest(fp_in);
  (*Dtree).read_skew(fp_in);
  // (*Dtree).print_skew(stdout);
  if (branch == 1 && scale_factor > 1){
    (*Dtree).scale_skew(scale_factor);
    // (*Dtree).print_skew(stdout);
  }
  (*Dtree).read_corr(fp_in);
  // (*Dtree).print_corr(stdout);

  (*Dtree).build_tree(Flist,temp_filters);
  // printf("Flist = "); (*Flist).print(stdout); printf("\n");
  printf(" \tdone\n");
  
  delete(Flist);


// ****************************************************************************
//  START of IMPROVEMENTS implemented in ClassBench-ng
// ****************************************************************************

  // transform filter set into filter graph and insert source/destination
  // prefixes of filters into corresponding tries
  Filter_graph graph;
  Trie src_trie;
  Trie dst_trie;
  for (int i = 1; i <= temp_num_filters; i++) {
     graph.add_filter(&(temp_filters[i]));
     src_trie.insert(IP_prefix(temp_filters[i].sa, temp_filters[i].sa_len));
     dst_trie.insert(IP_prefix(temp_filters[i].da, temp_filters[i].da_len));
  }

  // get statistics of source and destination tries
  trie_stats src_trie_stats, dst_trie_stats;
  src_trie.get_stats(src_trie_stats);
  dst_trie.get_stats(dst_trie_stats);

  // initialize data structures for trie-related distributions
  vector<float> src_prefixes(129,0);
  vector<float> src_one_child(129,0);
  vector<float> src_two_children(129,0);
  vector<float> src_skew(129,0);
  vector<float> dst_prefixes(129,0);
  vector<float> dst_one_child(129,0);
  vector<float> dst_two_children(129,0);
  vector<float> dst_skew(129,0);

  // get source and destination prefix length distributions
  // Use prefix length distributions from already generated source and
  // destination prefix sets as ClassBench-generated rule sets follow them
  // quite precisely.
  for (int i = 0; i < 129; i++) {
     src_prefixes[i] = (float)src_trie_stats.classbench.prefix_lengths[i] /
                       (float)src_trie_stats.classbench.prefixes;
     dst_prefixes[i] = (float)dst_trie_stats.classbench.prefix_lengths[i] /
                       (float)dst_trie_stats.classbench.prefixes;
  }

  // get other src distributions
  // Copy the values that were already read from the parameter file into Stree.
  for (int i = 0; i < 129; i++) {
     src_one_child[i] = Stree->get_p1child()[i];
     src_two_children[i] = Stree->get_p2child()[i];
     src_skew[i] = Stree->get_skew()[i];
  }
  delete(Stree);

  // get other dst distributions
  // Copy the values that were already read from the parameter file into Dtree.
  for (int i = 0; i < 129; i++) {
     dst_one_child[i] = Dtree->get_p1child()[i];
     dst_two_children[i] = Dtree->get_p2child()[i];
     dst_skew[i] = Dtree->get_skew()[i];
  }
  delete(Dtree);

  // prune source and destination tries to 1/100 of the original prefix sets
  src_trie.prune(num_filters, src_prefixes, src_one_child,
                 src_two_children, src_skew);
  dst_trie.prune(num_filters, dst_prefixes, dst_one_child,
                 dst_two_children, dst_skew);

  // extend filter graph according to pruned tries
  trie_to_graph(src_trie.get_root(), true, "", &graph);
  trie_to_graph(dst_trie.get_root(), false, "", &graph);

  // modify the filter graph to conform with the flow network specification
  graph.to_flow_network();

  // compute maximum flow for the current flow network
  int max_flow = graph.max_flow();

  // auxiliary variables for construction of the set of pruned filters
  struct filter* pruned_filters = new struct filter[temp_num_filters+1];
  for (int i = 0; i < temp_num_filters+1; i++) {
    pruned_filters[i].num_ext_field = 0;
  }
  int pruned_filters_i = 1;

  /*
   * 1st phase of construction of the set of pruned filters
   */
  // iterate over all filters
  const node_list_item* node;
  node = graph.get_src_nodes();
  while (node != NULL) {
     neighbour_list_item* neighbour = node->neighbours;
     while (neighbour != NULL) {
        filter_list_item* filter = neighbour->filters;
        for (int i = 0; i < neighbour->flow; i++) {
           // leave the cycle if enough filters have been selected
           if (pruned_filters_i == num_filters+1) {
              break;
           }
           // copy filters from the maximum flow to the pruned_filters array
           copy_filter(pruned_filters[pruned_filters_i], *(filter->filter));
           pruned_filters_i++;
           filter = filter->next;
        }
        // leave the cycle if enough filters have been selected
        if (pruned_filters_i == num_filters+1) {
           break;
        }
        neighbour = neighbour->next;
     }
     // leave the cycle if enough filters have been selected
     if (pruned_filters_i == num_filters+1) {
        break;
     }
     node = node->next;
  }

  /*
   * 2nd phase of construction of the set of pruned filters
   */
  // auxiliary variables for looking for not fully utilized source prefixes
  neighbour_list_item* s_neighbour = (graph.get_s_node() != NULL) ?
                                     graph.get_s_node()->neighbours : NULL;
  // iterate over all destination prefixes
  node = graph.get_dst_nodes();
  while (node != NULL) {
     neighbour_list_item* neighbour = node->neighbours;
     if (neighbour != NULL) {
        int free_weight = neighbour->weight - neighbour->flow;
        // auxiliary variables for looking for not fully utilized filters with
        // current destination prefix
        const node_list_item* src_node = graph.get_src_nodes();
        neighbour_list_item* src_neighbour;
        filter_list_item* src_filter;
        int src_filter_index = 0;
        // for each not fully utilized destination prefix
        for (int i = 0; i < free_weight; i++) {
           // leave the cycle if enough filters have been selected
           if (pruned_filters_i == num_filters+1) {
              break;
           }

// FILTERS start --------------------------------------------------------------

           // iterate over all filters with current destination prefix
           while (src_node != NULL) {
              src_neighbour = src_node->neighbours;
              while (src_neighbour != NULL) {
                 if (src_neighbour->node->prefix == node->prefix) {
                    src_filter = src_neighbour->filters;
                    // skip over all filters from the maximum flow
                    for (;
                         src_filter_index < src_neighbour->flow;
                         src_filter_index++) {
                       src_filter = src_filter->next;
                    }
                    if (src_filter != NULL) {// this filter is not fully
                                             // utilized

// SOURCE PREFIXES start ------------------------------------------------------

                       // find the first not fully utilized source prefix
                       while (s_neighbour != NULL) {
                          // if this source prefix is not fully utilized
                          if (s_neighbour->flow < s_neighbour->weight) {
                             // create local copy of the selected filter and
                             // modify its source prefix
                             struct filter pruned_filter;
                             copy_filter(pruned_filter, *(src_filter->filter));
                             pruned_filter.sa =
                                s_neighbour->node->prefix.get_prefix_uint128_t();
                             pruned_filter.sa_len =
                                s_neighbour->node->prefix.get_length();
                             // inset the filter into the pruned_filters array
                             pruned_filters[pruned_filters_i++] =
                                pruned_filter;
                             // increment flow value through used edges
                             s_neighbour->flow++;
                             src_neighbour->flow++;
                             neighbour->flow++;
                             // terminate looking for the next not fully
                             // utilized source prefix
                             break;
                          }
                          s_neighbour = s_neighbour->next;
                       }
                       // always terminate looking for not fully utilized
                       // filters because of the following reasons:
                       //    * if not fully utilized source prefix was found,
                       //      move to the next not fully utilized destination
                       //      prefix
                       //    * if not fully utilized source prefix was not
                       //      found, terminate inserting filters into the
                       //      pruned_filters array at all
                       break;

// SOURCE PREFIES end ---------------------------------------------------------

                    } else { // this filter is fully utilized
                       src_filter_index = 0;
                    }
                 }
                 src_neighbour = src_neighbour->next;
              }
              // if the previous cycle was broken, break also this cycle
              // (because of the same reasons)
              if (src_neighbour != NULL) {
                 break;
              }
              src_node = src_node->next;
           }
           // if either all filters or prefixes are fully utilized, terminate
           // looking for not fully utilized filters
           if ((src_node == NULL) || (s_neighbour == NULL)) {
              break;
           }

// FILTERS end ----------------------------------------------------------------

        }
     }
     // if all source prefixes are fully utilized or enough filters have been
     // selected, terminate looking for not fully utilized destination prefixes
     if ((s_neighbour == NULL) || (pruned_filters_i == num_filters+1)) {
        break;
     }
     node = node->next;
  }

// ****************************************************************************
//  END of IMPROVEMENTS implemented in ClassBench-ng
// ****************************************************************************


  printf("Removing redundant filters and ordering nested filters...\n");
  int filter_cnt = remove_redundant_filters(pruned_filters_i-1,filters,pruned_filters);
  printf(" \tdone\n");

  // Resolve conflicts, throw away filters if necessary
  // Final filter set may be smaller than target
  // printf("Resolving conflicts...\n");
  // resolve_conflicts(temp_filter);
  // printf(" \tdone\n");

  // Delete data structures
  for (int i = 0; i < temp_num_filters+1; i++) {
    if (temp_filters[i].num_ext_field > 0) {
      delete[] (temp_filters[i].ext_field);
    }
    if (pruned_filters[i].num_ext_field > 0) {
      delete[] (pruned_filters[i].ext_field);
    }
  }
  delete[] (temp_filters);
  delete[] (pruned_filters);
  // printf("Done with custom_db\n");

  return filter_cnt;
}

// Biased random number generator
double random_scope(float scope_x){

  // Seed random number generator with long int
  double p;
  // Get random number [0,1]
  p = drand48();

  // Generate biased random number
  double pb;
  pb = p*((scope_x*p) - scope_x + 1);

  return pb;
}

// Port selection
void select_ports(int port_type, struct filter *temp_filter, PortList *sparL, PortList *spemL, PortList *dparL, PortList *dpemL){
  double p;

  struct range temp_range;

  if (port_type == 0){
    // wc_wc
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 1){
    // wc_hi
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 1024;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 2){
    // hi_wc
    temp_filter->sp[0] = 1024;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 3){
    // hi_hi
    temp_filter->sp[0] = 1024;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 1024;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 4){
    // wc_lo
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 1023;
  } else if (port_type == 5){
    // lo_wc
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 1023;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 6){
    // hi_lo
    temp_filter->sp[0] = 1024;
    temp_filter->sp[1] = 65535;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 1023;
  } else if (port_type == 7){
    // lo_hi
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 1023;
    temp_filter->dp[0] = 1024;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 8){
    // lo_lo
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 1023;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 1023;
  } else if (port_type == 9){
    // wc_ar
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 65535;
    // Choose arbitrary destination port range
    p = drand48();
    temp_range = dparL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 10){
    // ar_wc
    // Choose arbitrary source port range
    p = drand48();
    temp_range = sparL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 11){
    // hi_ar
    temp_filter->sp[0] = 1024;
    temp_filter->sp[1] = 65535;
    // Choose arbitrary destination port range
    p = drand48();
    temp_range = dparL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 12){
    // ar_hi
    // Choose arbitrary source port range
    p = drand48();
    temp_range = sparL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 1024;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 13){
    // wc_em
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 65535;
    // Choose exact destination port range
    p = drand48();
    temp_range = dpemL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 14){
    // em_wc
    // Choose exact source port range
    p = drand48();
    temp_range = spemL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 15){
    // hi_em
    temp_filter->sp[0] = 1024;
    temp_filter->sp[1] = 65535;
    // Choose exact destination port range
    p = drand48();
    temp_range = dpemL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 16){
    // em_hi
    // Choose exact source port range
    p = drand48();
    temp_range = spemL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 1024;
    temp_filter->dp[1] = 65535;
  } else if (port_type == 17){
    // lo_ar
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 1023;
    // Choose arbitrary destination port range
    p = drand48();
    temp_range = dparL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 18){
    // ar_lo
    // Choose arbitrary source port range
    p = drand48();
    temp_range = sparL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 1023;
  } else if (port_type == 19){
    // lo_em
    temp_filter->sp[0] = 0;
    temp_filter->sp[1] = 1023;
    // Choose exact destination port range
    p = drand48();
    temp_range = dpemL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 20){
    // em_lo
    // Choose exact source port range
    p = drand48();
    temp_range = spemL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    temp_filter->dp[0] = 0;
    temp_filter->dp[1] = 1023;
  } else if (port_type == 21){
    // ar_ar
    // Choose arbitrary source port range
    p = drand48();
    temp_range = sparL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    // Choose arbitrary destination port range
    p = drand48();
    temp_range = dparL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 22){
    // ar_em
    // Choose arbitrary source port range
    p = drand48();
    temp_range = sparL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    // Choose exact destination port range
    p = drand48();
    temp_range = dpemL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 23){
    // em_ar
    // Choose exact source port range
    p = drand48();
    temp_range = spemL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    // Choose arbitrary destination port range
    p = drand48();
    temp_range = dparL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else if (port_type == 24){
    // em_em
    // Choose exact source port range
    p = drand48();
    temp_range = spemL->choose_port(p);
    temp_filter->sp[0] = temp_range.low;
    temp_filter->sp[1] = temp_range.high;
    // Choose exact destination port range
    p = drand48();
    temp_range = dpemL->choose_port(p);
    temp_filter->dp[0] = temp_range.low;
    temp_filter->dp[1] = temp_range.high;
  } else {
    fprintf(stderr,"ERROR (select_ports): port_type %d out of range\n",port_type);
    exit(1);
  }
  return;
}

void fprint_filter(FILE *fp, struct filter *filt){
  uint128_t temp;

  // Print new filter character
  fprintf(fp,"@");
  // Print source/destination address
  if (ADDRLEN == 32) { // IPv4
     // Source address
     temp = filt->sa >> 96;
     ip::address_v4 src_addr(temp);
     fprintf(fp, "%s/%d\t", src_addr.to_string().c_str(), (filt->sa_len < 32) ? filt->sa_len : 32);
     // Destination address
     temp = filt->da >> 96;
     ip::address_v4 dst_addr(temp);
     fprintf(fp, "%s/%d\t", dst_addr.to_string().c_str(), (filt->da_len < 32) ? filt->da_len : 32);
  } else { // IPv6
     // Source address
     temp = filt->sa;
     const ip::address_v6::bytes_type src_temp_bytes_type(
        (unsigned char) (temp.upper() >> 56),
        (unsigned char) (temp.upper() >> 48),
        (unsigned char) (temp.upper() >> 40),
        (unsigned char) (temp.upper() >> 32),
        (unsigned char) (temp.upper() >> 24),
        (unsigned char) (temp.upper() >> 16),
        (unsigned char) (temp.upper() >>  8),
        (unsigned char)  temp.upper(),
        (unsigned char) (temp.lower() >> 56),
        (unsigned char) (temp.lower() >> 48),
        (unsigned char) (temp.lower() >> 40),
        (unsigned char) (temp.lower() >> 32),
        (unsigned char) (temp.lower() >> 24),
        (unsigned char) (temp.lower() >> 16),
        (unsigned char) (temp.lower() >>  8),
        (unsigned char)  temp.lower());
     ip::address_v6 src_addr(src_temp_bytes_type);
     fprintf(fp, "%s/%d\t", src_addr.to_string().c_str(), filt->sa_len);
     // Destination address
     temp = filt->da;
     const ip::address_v6::bytes_type dst_temp_bytes_type(
        (unsigned char) (temp.upper() >> 56),
        (unsigned char) (temp.upper() >> 48),
        (unsigned char) (temp.upper() >> 40),
        (unsigned char) (temp.upper() >> 32),
        (unsigned char) (temp.upper() >> 24),
        (unsigned char) (temp.upper() >> 16),
        (unsigned char) (temp.upper() >>  8),
        (unsigned char)  temp.upper(),
        (unsigned char) (temp.lower() >> 56),
        (unsigned char) (temp.lower() >> 48),
        (unsigned char) (temp.lower() >> 40),
        (unsigned char) (temp.lower() >> 32),
        (unsigned char) (temp.lower() >> 24),
        (unsigned char) (temp.lower() >> 16),
        (unsigned char) (temp.lower() >>  8),
        (unsigned char)  temp.lower());
     ip::address_v6 dst_addr(dst_temp_bytes_type);
     fprintf(fp, "%s/%d\t", dst_addr.to_string().c_str(), filt->da_len);
  }
  // Print source port 
  fprintf(fp, "%d : %d\t",
	  filt->sp[0], filt->sp[1]);
  // Print destination port 
  fprintf(fp, "%d : %d\t",
	  filt->dp[0], filt->dp[1]);
  // Print protocol 
  fprintf(fp, "%d",
	  filt->prot_num);    
  // Print newline 
  fprintf(fp,"\n");

  return;
}

int read_scale(FILE *fp){
  int done = 0;
  int matches = 0;
  char comm[7];
  char scale_comm[]="-scale";
  int scale = 0;

  // read in scale
  while (matches != EOF && done == 0) {
    matches = fscanf(fp,"%s",comm);
    if (strcmp(comm,scale_comm) == 0) done = 1;
  }
  if (matches == EOF) {
    fprintf(stderr,"Warning: Could not find -scale identifier.\n");
    return scale;
  }
  done = 0;
  // char scomm[500];
  // int scomm_len = 500;
  while (done == 0) {
    // Read a line of the input
    // printf("Reading a line from the input file...\n");
    // fgets(scomm,scomm_len,fp);
    // Read a line of the input
    // matches = sscanf(scomm,"%d",&scale);
    matches = fscanf(fp,"%d",&scale);
    if (matches == 1) done = 1;
  }
  return scale;
}

int remove_redundant_filters(int num_filters, FilterList* filters, filter* temp_filters){
  int filter_cnt = 0;
  int redundant, nest, flag;
  FiveTuple* ftuple = new FiveTuple;
  dlist* TupleListPtr;
  dlist** TupleListPtrArray;
  TupleBST* TupleTree = new TupleBST;
  // For all filters in temp_filters
  for (int i = 1; i <= num_filters; i++){
    // Determine filter tuple
    ftuple->sa_len = temp_filters[i].sa_len;
    ftuple->da_len = temp_filters[i].da_len;
    ftuple->sp_wid = temp_filters[i].sp[1] - temp_filters[i].sp[0] + 1;
    ftuple->dp_wid = temp_filters[i].dp[1] - temp_filters[i].dp[0] + 1;
    if (temp_filters[i].prot_num > 0) ftuple->prot = 1;
    else ftuple->prot = 0;
    if (temp_filters[i].flags_mask > 0) ftuple->flag = 1;
    else ftuple->flag = 0;
    // Get pointer for tuple list
    TupleListPtr = TupleTree->Insert(ftuple);
    if (TupleListPtr == NULL) {fprintf(stderr,"ERROR: TupleBST::Insert returned a null pointer."); exit(1);}

    // Check for redundant filters in tuple list
    dlist_item* findex;
    int rflag = 0;
    for (findex = (*TupleListPtr)(1); findex != NULL && rflag == 0; findex = findex->next){
      redundant = nest = 0;
      // Check for redundancy
      rflag = redundant_check(temp_filters[i],temp_filters[findex->key]);
    }
    // If not redundant add to tuple list
    if (rflag == 0) {(*TupleListPtr)&=i; filter_cnt++;}
  }
  // Sort tuple set pointers by specificity (most to least)
  TupleListPtrArray = TupleTree->GetTupleLists();

  // Append filters to FilterList in order of most-specific tuple to least specific tuple
  for (int i = 0; i < TupleTree->size(); i++){
    TupleListPtr = TupleListPtrArray[i];
    if (TupleListPtr == NULL) {fprintf(stderr,"ERROR: TupleListPtrArray contains a null pointer."); exit(1);}
    dlist_item* findex;
    for (findex = (*TupleListPtr)(1); findex != NULL; findex = findex->next){
      (*filters)&=temp_filters[findex->key];
    }
  }
  delete(ftuple);
  delete(TupleTree);
  return filter_cnt;
}
