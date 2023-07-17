// filter_graph.cc: Filter_graph class definition
//
// Jiri Matousek, 2017
// imatousek@fit.vutbr.cz


// User includes
#include "stdinc.h"
#include "flow_network.h"
#include "filter_graph.h"

// Library includes
#include <queue>
#include <iostream>

// Default namespace
using namespace std;


// ****************************************************************************
//                            Function definitions
// ****************************************************************************


// ***** Auxiliary (non-member) functions *************************************


/*
 * Private function that builds a flow network corresponding to the filter
 * graph.
 * In three iterations the function traverses all edges of the filter graph
 * (i.e., s_node->src_nodes, src_nodes->dst_nodes, and dst_nodes->t_node edges)
 * and constructs the flow network corresponding to this graph. Each edge of
 * the filter graph can be represented by at most two edges of the flow
 * network -- a forward and backward edge. Note that they are included into the
 * flow network only if their residual capacity is greater than zero.
 * The function expects that the input graph is already a valid flow network,
 * i.e., it contains only one node without input edges (the 's' node) and only
 * one node without output edges (the 't' node).
 * @param network   Reference to the (most probably empty) flow network object.
 * @param graph     Pointer to the constant filter graph object.
 */
void build_flow_network(Flow_network& network, const Filter_graph* graph) {
   // declatarion of "phase" variables
   const node_list_item* list;
   int src_list;
   int dst_list;

   // iteration through three phases
   for (int i = 0; i < 3; i++) {
      // setting of phase variables
      switch (i) {
         case 0: // edges from the 's' node to destination nodes
            list = graph->get_s_node();
            src_list = 0;
            dst_list = 1;
            break;
         case 1: // edges from source nodes to destination nodes
            list = graph->get_src_nodes();
            src_list = 1;
            dst_list = 2;
            break;
         case 2: // edges from destination nodes to the 'd' node
            list = graph->get_dst_nodes();
            src_list = 2;
            dst_list = 3;
            break;
      }

      // iteration over all nodes in the list
      while (list != NULL) {
         neighbour_list_item* neighbour = list->neighbours;
         // iteration over all neighbours (i.e., edges of the filter graph)
         while (neighbour != NULL) {
            // compute residual capacity of forward and backward edges
            int capacity_forward = neighbour->weight - neighbour->flow;
            int capacity_backward = neighbour->flow;
            // insert the forward edge, if it has capacity > 0
            if (capacity_forward > 0) {
               network.add_edge(list->prefix, src_list,
                                neighbour->node->prefix, dst_list,
                                neighbour, true, capacity_forward);
            }
            // insert the backward edge, if it has capacity > 0
            if (capacity_backward > 0) {
               network.add_edge(neighbour->node->prefix, dst_list,
                                list->prefix, src_list,
                                neighbour, false, capacity_backward);
            }
            // move to the next edge
            neighbour = neighbour->next;
         }
         // move to the next node
         list = list->next;
      }
   }
} // end build_flow_network()


// ***** Private functions ****************************************************


/*
 * Private static function that creates deep copy of the original list.
 */
node_list_item* Filter_graph::copy_node_list(const node_list_item* orig) {
   // initialize pointer to copied node list
   node_list_item* result = (orig == NULL) ?
                            NULL :
                            new node_list_item;

   // node list level of copying
   node_list_item* copy = result;
   while (orig != NULL) {
      // list item members initialization
      copy->prefix = orig->prefix;
      copy->pruned = orig->pruned;
      copy->neighbours = (orig->neighbours == NULL) ?
                         NULL :
                         new neighbour_list_item;
      copy->next   = (orig->next == NULL) ?
                     NULL :
                     new node_list_item;

      // neighbour list level of copying
      neighbour_list_item* orig_neighbours = orig->neighbours;
      neighbour_list_item* copy_neighbours = copy->neighbours;
      while (orig_neighbours != NULL) {
         // list item members initialization
         copy_neighbours->node = NULL; // cannot be initialized directly
                                       // (points to different node list)
         copy_neighbours->weight = orig_neighbours->weight;
         copy_neighbours->flow = orig_neighbours->flow;
         copy_neighbours->filters = (orig_neighbours->filters == NULL) ?
                                    NULL :
                                    new filter_list_item;
         copy_neighbours->next = (orig_neighbours->next == NULL) ?
                                 NULL :
                                 new neighbour_list_item;

         // filter list level of copying
         filter_list_item* orig_filters = orig_neighbours->filters;
         filter_list_item* copy_filters = copy_neighbours->filters;
         while (orig_filters != NULL) {
            // list item members initialization
            copy_filters->filter = orig_filters->filter;
            copy_filters->next = (orig_filters->next == NULL) ?
                            NULL :
                            new filter_list_item;
            // move to the next item of filter list
            copy_filters = copy_filters->next;
            orig_filters = orig_filters->next;
         }

         // move to the next item of neighbour list
         copy_neighbours = copy_neighbours->next;
         orig_neighbours = orig_neighbours->next;
      }

      // move to the next item of node list
      copy = copy->next;
      orig = orig->next;
   }

   return result;
} // end copy_node_list()


/*
 * Private static function that correctly deallocates the whole node list.
 */
void Filter_graph::remove_node_list(node_list_item** list) {
   // traverse all nodes
   while ((*list) != NULL) {
      // get pointer to the first node
      node_list_item* first_node = *list;

      // correctly deallocate its whole neighbour list
      remove_neighbour_list(&(first_node->neighbours));

      // move to the next node list item and deallocate the current one
      node_list_item* next_node = first_node->next;
      delete first_node;
      *list = next_node;
   }
} // end remove_node_list()


/*
 * Private static function that correctly deallocates the whole neighbour
 * list.
 */
void Filter_graph::remove_neighbour_list(neighbour_list_item** list) {
   // traverse all neighbours
   while ((*list) != NULL) {
      // get pointer to the first neighbour
      neighbour_list_item* first_neighbour = *list;

      // correctly deallocate it whole filter list
      remove_filter_list(&(first_neighbour->filters));

      // move to the next neighbour list item and deallocate the current one
      neighbour_list_item* next_neighbour = first_neighbour->next;
      delete first_neighbour;
      *list = next_neighbour;
   }
} // end remove_neighbour_list()


/*
 * Private static function that correctly deallocates the whole filter list.
 */
void Filter_graph::remove_filter_list(filter_list_item** list) {
   // traverse all filters
   while ((*list) != NULL) {
      // get pointer to the first filter
      filter_list_item* first_filter = *list;

      // move to the next filter list item and deallocate the current one
      filter_list_item* next_filter = first_filter->next;
      delete first_filter;
      *list = next_filter;
   }
} // end remove_filter_list()


/*
 * Private static function that sets correct values of neighbour node pointers,
 * which cannot be correctly initialized during copying.
 */
void Filter_graph::set_neighbour_nodes(const node_list_item* orig,
                                             node_list_item* src,
                                             node_list_item* dst) {
   // traverse all nodes
   while (orig != NULL) {
      neighbour_list_item* orig_neighbours = orig->neighbours;
      neighbour_list_item* src_neighbours = src->neighbours;

      // traverse all neighbours
      while (orig_neighbours != NULL) {
         // set correct neighbour node pointer
         src_neighbours->node = find_node(orig_neighbours->node->prefix, dst);

         // move to the next item of neighbour list
         orig_neighbours = orig_neighbours->next;
         src_neighbours = src_neighbours->next;
      }

      // move to the next item of node list
      orig = orig->next;
      src = src->next;
   }

   return;
} // end set_neighbour_nodes()


/*
 * Private static function that looks for node with the given prefix in the
 * given list of nodes.
 */
node_list_item* Filter_graph::find_node(const IP_prefix& prefix,
                                              node_list_item* list) {
   // traverse all nodes
   while (list != NULL) {
      if (list->prefix == prefix) {
         // corresponding node - return pointer to it
         return list;
      } else {
         // node with different prefix - move to the next item of node list
         list = list->next;
      }
   }

   // return NULL if corresponding node was not found
   return NULL;
} // end find_node()


/*
 * Private static function that looks for the corresponding neighbour node in
 * the given list of neighbours.
 */
neighbour_list_item* Filter_graph::find_neighbour(
                                      const node_list_item* neighbour,
                                      neighbour_list_item* list) {
   // traverse all neighbour nodes
   while (list != NULL) {
      if (list->node->prefix == neighbour->prefix) {
         // corresponding neighbour node - return pointer to it
         return list;
      } else {
         // neighbour node corresponding to different prefix node - move to the
         // next item of neighbour list
         list = list->next;
      }
   }

   // return NULL if corresponding neighbour node was not found
   return NULL;
} // end find_neighbour()


/*
 * Private static function that looks for the filter node pointing to the
 * specified filter in the given list of filters.
 */
filter_list_item* Filter_graph::find_filter(const struct filter* filter,
                                            filter_list_item* list) {
   // traverse all filter nodes
   while (list != NULL) {
      if (list->filter == filter) {
         // corresponding filter node - return pointer to it
         return list;
      } else {
         // filter node pointing to different filter - move to the next item of
         // filter list
         list = list->next;
      }
   }

   // return NULL if corresponding filter node was not found
   return NULL;
} // end find_filter()


/*
 * Private static function that inserts a node representing the given IP prefix
 * at the beginning of the given list of nodes.
 */
void Filter_graph::insert_node(const IP_prefix& prefix,
                               node_list_item** list) {
   // allocate and initialize new prefix node
   node_list_item* node = new node_list_item;
   node->prefix = prefix;
   node->pruned = false;
   node->neighbours = NULL;

   // insert new prefix node at the beginning of the list
   node->next = *list;
   *list = node;

   return;
} // end insert_node()


/*
 * Private static function that inserts a neighbour node corresponding to the
 * given prefix node at the beginning of the given list of neighbour nodes.
 */
void Filter_graph::insert_neighbour(node_list_item* neighbour,
                                    neighbour_list_item** list) {
   // allocate and initialize new neighbour node
   neighbour_list_item* node = new neighbour_list_item;
   node->node = neighbour;
   node->weight = 0;
   node->flow = 0;
   node->filters = NULL;

   // insert new neighbour node at the beginning of the list
   node->next = *list;
   *list = node;

   return;
} // end insert_neighbour()


/*
 * Private static function that inserts a filter node pointing to the given
 * filter at the beginning of the given list of filter nodes.
 */
void Filter_graph::insert_filter(const struct filter* filter,
                                 filter_list_item** list) {
   // allocate and initialize new filter node
   filter_list_item* node = new filter_list_item;
   node->filter = filter;

   // insert new filter node at the beginning of the list
   node->next = *list;
   *list = node;

   return;
} // end insert_filter()


/*
 * Private static function that prints specified node list, including all
 * sublists (i.e., neighbour lists and filter lists).
 */
void Filter_graph::print_node_list(const node_list_item* nodes) {
   while (nodes != NULL) {
      // print node list items
      cout << "+-> " << nodes->prefix.get_prefix() << "/"
                     << nodes->prefix.get_length() << endl;
      neighbour_list_item* neighbours = nodes->neighbours;
      while (neighbours != NULL) {
         // print neighbour list items
         cout << "|   +-> " << neighbours->node->prefix.get_prefix() << "/"
                            << neighbours->node->prefix.get_length() << " "
                            << "("
                            << neighbours->flow << "/"
                            << neighbours->weight
                            << ")" << endl;
         filter_list_item* filters = neighbours->filters;
         while (filters != NULL) {
            // print filter list items
            cout << "|   |   +->  " << filters->filter->sp[0] << ":"
                                    << filters->filter->sp[1] << " "
                                    << filters->filter->dp[0] << ":"
                                    << filters->filter->dp[1] << " "
                                    << filters->filter->prot_num << endl;
            // move to the next filter
            filters = filters->next;
         }
         // moce tothe next neighbour
         neighbours = neighbours->next;
      }
      // move to the next node
      nodes = nodes->next;
   }
} // end print_node_list()


/*
 * Private function that removes non-pruned nodes and resets the "pruned"
 * flag of pruned nodes of the filter graph.
 */
void Filter_graph::remove_and_reset() {
   for (int i = 0; i < 4; i++) {
      // select the correct node list for iteration
      node_list_item** node_ptr;
      switch (i) {
         case 0:
            node_ptr = &s_node;
            break;
         case 1:
            node_ptr = &src_nodes;
            break;
         case 2:
            node_ptr = &dst_nodes;
            break;
         case 3:
            node_ptr = &t_node;
            break;
      }

      // iterate over all nodes in the list
      while ((*node_ptr) != NULL) {
         node_list_item* node = *node_ptr;
         if (node->pruned == false) { // remove the non-pruned node
            (*node_ptr) = node->next;
            delete node;
         } else { // reset the "pruned" flag of the pruned node
            node->pruned = false;
            node_ptr = &(node->next);
         }
      }
   }
} // end remove_and_reset()


// ***** Public functions *****************************************************


/*
 * Default constructor.
 */
Filter_graph::Filter_graph() {
   src_nodes = NULL;
   dst_nodes = NULL;
   s_node    = NULL;
   t_node    = NULL;
} // end Filter_graph()


/*
 * Copy constructor.
 */
Filter_graph::Filter_graph(const Filter_graph& orig) {
   // acquire members of the original object
   const node_list_item* orig_src_nodes = orig.get_src_nodes();
   const node_list_item* orig_dst_nodes = orig.get_dst_nodes();
   const node_list_item* orig_s_node = orig.get_s_node();
   const node_list_item* orig_t_node = orig.get_t_node();

   // copy member node lists one by one
   src_nodes = copy_node_list(orig_src_nodes);
   dst_nodes = copy_node_list(orig_dst_nodes);
   s_node = copy_node_list(orig_s_node);
   t_node = copy_node_list(orig_t_node);

   // set pointers to neighbour nodes
   set_neighbour_nodes(orig_t_node, t_node, NULL);
   set_neighbour_nodes(orig_dst_nodes, dst_nodes, t_node);
   set_neighbour_nodes(orig_src_nodes, src_nodes, dst_nodes);
   set_neighbour_nodes(orig_s_node, s_node, src_nodes);
} // end Filter_graph()


/*
 * Destructor.
 */
Filter_graph::~Filter_graph() {
   remove_node_list(&s_node);
   remove_node_list(&src_nodes);
   remove_node_list(&dst_nodes);
   remove_node_list(&t_node);
} // end ~Filter_graph()


/*
 * Copy assignment.
 */
Filter_graph& Filter_graph::operator=(const Filter_graph& copy) {
   // destruct the original object
   remove_node_list(&s_node);
   remove_node_list(&src_nodes);
   remove_node_list(&dst_nodes);
   remove_node_list(&t_node);

   // acquire members of the copied object
   const node_list_item* copy_src_nodes = copy.get_src_nodes();
   const node_list_item* copy_dst_nodes = copy.get_dst_nodes();
   const node_list_item* copy_s_node = copy.get_s_node();
   const node_list_item* copy_t_node = copy.get_t_node();

   // copy member node lists one by one
   src_nodes = copy_node_list(copy_src_nodes);
   dst_nodes = copy_node_list(copy_dst_nodes);
   s_node = copy_node_list(copy_s_node);
   t_node = copy_node_list(copy_t_node);

   // set pointers to neighbour nodes
   set_neighbour_nodes(copy_t_node, t_node, NULL);
   set_neighbour_nodes(copy_dst_nodes, dst_nodes, t_node);
   set_neighbour_nodes(copy_src_nodes, src_nodes, dst_nodes);
   set_neighbour_nodes(copy_s_node, s_node, src_nodes);

   // return the original object with new content
   return *this;
} // end operator=()


/*
 * Modifies filter graph to add the specified filter into the set of filters
 * represented by the graph.
 */
void Filter_graph::add_filter(const struct filter* filter) {
   // acquire source and destination prefixes
   IP_prefix src_pref(filter->sa, filter->sa_len);
   IP_prefix dst_pref(filter->da, filter->da_len);

   // find source prefix node and insert such node if it does not exist
   node_list_item* src_node = find_node(src_pref, src_nodes);
   if (src_node == NULL) {
      // node is inserted at the beginning of the list
      insert_node(src_pref, &src_nodes);
      src_node = src_nodes;
   }

   // find destination prefix node and insert such node if it does not exist
   node_list_item* dst_node = find_node(dst_pref, dst_nodes);
   if (dst_node == NULL) {
      // node is inserted at the beginning of the list
      insert_node(dst_pref, &dst_nodes);
      dst_node = dst_nodes;
   }

   // find neighbour node corresponding to the filter and insert such node if
   // it does not exist
   neighbour_list_item* neighbour = find_neighbour(dst_node,
                                                   src_node->neighbours);
   if (neighbour == NULL) {
      // neighbour is inserted at the beginning of the list
      insert_neighbour(dst_node, &(src_node->neighbours));
      neighbour = src_node->neighbours;
   }

   // find filter node pointing to the specified filter and insert such node if
   // it does not exist
   filter_list_item* filter_node = find_filter(filter, neighbour->filters);
   if (filter_node == NULL) {
      insert_filter(filter, &(neighbour->filters));
      neighbour->weight += 1;
   }
} // end add_filter()


/*
 * Adds an edge from the 's' node to a node representing the given prefix
 * within the source nodes list and sets its weight to the given value.
 */
void Filter_graph::add_s_prefix(const IP_prefix& prefix, const int weight) {
   // check existence of the 's' node and allocate it if it does not exist
   if (s_node == NULL) {
     insert_node(IP_prefix(), &s_node);
     s_node->pruned = true;
   }

   // find a node representing the given prefix within the source nodes list
   // (existence of such node is not checked since it should always exist)
   node_list_item* src_node = find_node(prefix, src_nodes);

   // find a neighbour node corresponding to the given prefix
   neighbour_list_item* neighbour = find_neighbour(src_node,
                                                   s_node->neighbours);
   if (neighbour == NULL) { // the neighbour node does not exist
      // insert the node at the beginning of the list
      insert_neighbour(src_node, &(s_node->neighbours));
      neighbour = s_node->neighbours;
      // set neighbour node's weight member
      neighbour->weight = weight;
   } else { // the neighbour node exists
      // adjust neighbour node's weight member accordingly
      neighbour->weight += weight;
   }

   // set source node's pruned flag to true
   src_node->pruned = true;
} // end add_s_prefix()


/*
 * Adds an edge from a node representing the given prefix within the
 * destination nodes list to the 't' node and sets its weight to the given
 * value.
 */
void Filter_graph::add_t_prefix(const IP_prefix& prefix, const int weight) {
   // check existence of the 't' node and allocate it if it does not exist
   if (t_node == NULL) {
     insert_node(IP_prefix(), &t_node);
     t_node->pruned = true;
   }

   // find a node representing the given prefix within the destination nodes
   // list
   // (existence of such node is not checked since it should always exist)
   node_list_item* dst_node = find_node(prefix, dst_nodes);

   // find a neighbour node corresponding to the 't' node
   neighbour_list_item* neighbour = find_neighbour(t_node,
                                                   dst_node->neighbours);
   if (neighbour == NULL) { // the neighbour node does not exist
      // insert the node at the beginning of the list
      insert_neighbour(t_node, &(dst_node->neighbours));
      neighbour = dst_node->neighbours;
      // set neighbour node's weight member
      neighbour->weight = weight;
   } else { // the neighbour node exists
      // adjust neighbour node's weight member accordingly
      neighbour->weight += weight;
   }

   // set destination node's pruned flag to true
   dst_node->pruned = true;
} // end add_t_prefix()


/*
 * Modifies the filter graph such that it conforms with the flow network
 * specification -- i.e., it has only one node without input edges (the
 * 's' node) and only one node without output edges (the 't' node).
 */
void Filter_graph::to_flow_network() {
   // 1) remove filters containing at least one non-pruned prefix
   node_list_item* node = src_nodes;
   while (node != NULL) {
      if (node->pruned == false) { // remove all neighbours of this node
         remove_neighbour_list(&(node->neighbours));
      } else { // remove only neighbours pointing to a non-pruned node
         neighbour_list_item** neighbour_ptr = &(node->neighbours);
         while ((*neighbour_ptr) != NULL) {
            neighbour_list_item* neighbour = *neighbour_ptr;
            if (neighbour->node->pruned == false) { // remove this neighbour
               remove_filter_list(&(neighbour->filters));
               *neighbour_ptr = neighbour->next;
               delete neighbour;
            } else { // just move to the next neighbour
               neighbour_ptr = &(neighbour->next);
            }
         }
      }
      node = node->next;
   }

   // 2) remove non-pruned nodes and reset the "pruned" flag of other nodes
   remove_and_reset();

   // 3) BFS to set the "pruned" flag of visited nodes with at least one
   //    neighbour and the 's' and 't' nodes
   queue<node_list_item*> q;
   q.push(s_node);
   // do the BFS
   while (!q.empty()) {
      // dequeue the front element of the queue
      node_list_item* node = q.front();
      q.pop();
      // set the "pruned" flag if the list of neighbours is non-empty
      if (node->neighbours != NULL) {
         node->pruned = true;
      }
      // insert neighbours into the queue
      neighbour_list_item* neighbour = node->neighbours;
      while (neighbour != NULL) {
         q.push(neighbour->node);
         neighbour = neighbour->next;
      }
   }
   // set the "pruned" flag of the 's' and 't' nodes
   s_node->pruned = true;
   t_node->pruned = true;

   // 4) remove edges from the 's' node going to non-pruned nodes
   neighbour_list_item** neighbour_ptr = &(s_node->neighbours);
   while ((*neighbour_ptr) != NULL) {
      neighbour_list_item* neighbour = *neighbour_ptr;
      if (neighbour->node->pruned == false) { // remove this edge
         // there are no filters represented by edges from the 's' node
         (*neighbour_ptr) = neighbour->next;
         delete neighbour;
      } else { // move to the next edge
         neighbour_ptr = &(neighbour->next);
      }
   }

   // 5) remove edges to the 't' node going from non-pruned nodes
   node = dst_nodes;
   while (node != NULL) {
      if (node->pruned == false) { // remove all edges going from this node
         remove_neighbour_list(&(node->neighbours));
      }
      // move to the next node
      node = node->next;
   }

   // 6) remove non-pruned nodes (and reset the "pruned" flag of other nodes)
   remove_and_reset();
} // end to_flow_network()


/*
 * Computes maximum flow using Dinic's algorithm.
 */
int Filter_graph::max_flow() {
   int max_flow = 0;
   int flow_inc;

   do { // iterate until the flow cannot be improved
      // build flow network corresponding to the filter graph
      Flow_network network;
      build_flow_network(network, this);

      // transform the flow network into the level graph
      network.to_level_graph();

      // compute a blocking flow in the flow network and update the flow in the
      // filter graph accordingly
      flow_inc = network.find_blocking_flow();
      max_flow += flow_inc;
   } while (flow_inc != 0);

   return max_flow;
} // end max_flow()


/*
 * Prints the filter graph.
 */
void Filter_graph::print() {
   cout << "S_NODE:" << endl;
   print_node_list(s_node);
   cout << "--------------------" << endl;

   cout << "SRC_NODES:" << endl;
   print_node_list(src_nodes);
   cout << "--------------------" << endl;

   cout << "DST_NODES:" << endl;
   print_node_list(dst_nodes);
   cout << "--------------------" << endl;

   cout << "T_NODE:" << endl;
   print_node_list(t_node);
   cout << "--------------------" << endl;
}
