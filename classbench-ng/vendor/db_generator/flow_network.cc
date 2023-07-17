// flow_network.cc: Flow_network class definition
//
// Jiri Matousek, 2017
// imatousek@fit.vutbr.cz


// User includes
#include "flow_network.h"

// Library includes
#include <queue>
#include <stack>
#include <list>
#include <iostream>

// Default namespace
using namespace std;


// ****************************************************************************
//                            Function definitions
// ****************************************************************************


// ***** Private functions (related to filter graph) **************************


/*
 * Private static function that creates deep copy of the original list.
 */
net_node_list_item* Flow_network::copy_node_list(const net_node_list_item* orig) {
   // initialize pointer to copied node list
   net_node_list_item* result = (orig == NULL) ?
                                NULL :
                                new net_node_list_item;

   // node list level of copying
   net_node_list_item* copy = result;
   while (orig != NULL) {
      // list item members initialization
      copy->prefix = orig->prefix;
      copy->visited = orig->visited;
      copy->neighbours = (orig->neighbours == NULL) ?
                         NULL :
                         new net_neighbour_list_item;
      copy->next = (orig->next == NULL) ?
                   NULL :
                   new net_node_list_item;

      // neighbour list level of copying
      net_neighbour_list_item* orig_neighbours = orig->neighbours;
      net_neighbour_list_item* copy_neighbours = copy->neighbours;
      while (orig_neighbours != NULL) {
         // list item members initialization
         copy_neighbours->src_node = copy;
         copy_neighbours->dst_node = NULL; // cannot be initialized directly
                                           // (points to different node list)
         copy_neighbours->capacity = orig_neighbours->capacity;
         copy_neighbours->flow = orig_neighbours->flow;
         copy_neighbours->orig_edge = orig_neighbours->orig_edge;
         copy_neighbours->forward_edge = orig_neighbours->forward_edge;
         copy_neighbours->next = (orig_neighbours->next == NULL) ?
                                 NULL :
                                 new net_neighbour_list_item;

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
void Flow_network::remove_node_list(net_node_list_item* list) {
   // traverse all nodes
   while (list != NULL) {
      net_neighbour_list_item* neighbours = list->neighbours;

      // traverse all neighbours
      while (neighbours != NULL) {
         // move to the next neighbour list item and deallocate the current one
         net_neighbour_list_item* current_neighbour = neighbours;
         neighbours = neighbours->next;
         delete current_neighbour;
      }

      // move to the next node list item and deallocate the current one
      net_node_list_item* current_node = list;
      list = list->next;
      delete current_node;
   }

   return;
} // end remove_node_list()


/*
 * Private static function that sets correct values of destination node
 * pointers, which cannot be correctly initialized during copying.
 */
void Flow_network::set_destination_nodes(const net_node_list_item* orig,
                                               net_node_list_item* copy,
                                               net_node_list_item* prev,
                                               net_node_list_item* next) {
   // traverse all nodes
   while (orig != NULL) {
      net_neighbour_list_item* orig_neighbours = orig->neighbours;
      net_neighbour_list_item* copy_neighbours = copy->neighbours;

      // traverse all neighbours
      while (orig_neighbours != NULL) {
         // set correct destination node pointer
         if (orig_neighbours->forward_edge) { // forward edge
            copy_neighbours->dst_node =
               find_node(orig_neighbours->dst_node->prefix, next);
         } else { // backward edge
            copy_neighbours->dst_node =
               find_node(orig_neighbours->dst_node->prefix, prev);
         }

         // move to the next item of neighbour list
         orig_neighbours = orig_neighbours->next;
         copy_neighbours = copy_neighbours->next;
      }

      // move to the next item of node list
      orig = orig->next;
      copy = copy->next;
   }

   return;
} // end set_destination_nodes()


/*
 * Private static function that looks for node with the given prefix in the
 * given list of nodes.
 */
net_node_list_item* Flow_network::find_node(const IP_prefix& prefix,
                                            net_node_list_item* list) {
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
net_neighbour_list_item* Flow_network::find_neighbour(
                                          const net_node_list_item* neighbour,
                                          net_neighbour_list_item* list) {
   // traverse all neighbour nodes
   while (list != NULL) {
      if (list->dst_node->prefix == neighbour->prefix) {
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
 * Private static function that inserts a node representing the given IP prefix
 * at the beginning of the given list of nodes.
 */
void Flow_network::insert_node(const IP_prefix& prefix,
                               net_node_list_item** list) {
   // allocate and initialize new prefix node
   net_node_list_item* node = new net_node_list_item;
   node->prefix = prefix;
   node->visited = false;
   node->neighbours = NULL;

   // insert new prefix node at the beginning of the list
   node->next = *list;
   *list = node;

   return;
} // end insert_node()


/*
 * Private static function that inserts a neighbour node representing an edge
 * between the given source and destination nodes at the beginning of the
 * specified list of neighbour nodes.
 */
void Flow_network::insert_neighbour(net_node_list_item* src_node,
                                    net_node_list_item* dst_node,
                                    int capacity,
                                    int flow,
                                    neighbour_list_item* orig_edge,
                                    bool forward_edge,
                                    net_neighbour_list_item** list) {
   // allocate and initialize new neighbour node
   net_neighbour_list_item* node = new net_neighbour_list_item;
   node->src_node = src_node;
   node->dst_node = dst_node;
   node->capacity = capacity;
   node->flow = flow;
   node->orig_edge = orig_edge;
   node->forward_edge = forward_edge;

   // insert new neighbour node at the beginning of the list
   node->next = *list;
   *list = node;

   return;
} // end insert_neighbour()


/*
 * Private static function that prints specified node list, including all
 * sublists.
 */
void Flow_network::print_node_list(const net_node_list_item* nodes) {
   while (nodes != NULL) {
      // print node list items
      cout << "+-> " << nodes->prefix.get_prefix() << "/"
                     << nodes->prefix.get_length() << endl;
      net_neighbour_list_item* neighbours = nodes->neighbours;
      while (neighbours != NULL) {
         // print neighbour list items
         cout << "|   +-> ";
         if (neighbours->forward_edge) { // forward edge
            cout << "FORWARD: ";
         } else { // backward edge
            cout << "BACKWARD: ";
         }
         cout  << neighbours->src_node->prefix.get_prefix() << "/"
               << neighbours->src_node->prefix.get_length()
               << " --> "
               << neighbours->dst_node->prefix.get_prefix() << "/"
               << neighbours->dst_node->prefix.get_length()
               << " "
               << "("
               << neighbours->flow << "/"
               << neighbours->capacity
               << ")" << endl;
         // move to the next neighbour
         neighbours = neighbours->next;
      }
      // move to the next node
      nodes = nodes->next;
   }
} // end print_node_list()


// ***** Public functions *****************************************************


/*
 * Default constructor.
 */
Flow_network::Flow_network() {
   src_nodes = NULL;
   dst_nodes = NULL;
   s_node    = NULL;
   t_node    = NULL;
} // end Flow_network()


/*
 * Copy constructor.
 */
Flow_network::Flow_network(const Flow_network& orig) {
   // acquire members of the original object
   const net_node_list_item* orig_src_nodes = orig.get_src_nodes();
   const net_node_list_item* orig_dst_nodes = orig.get_dst_nodes();
   const net_node_list_item* orig_s_node = orig.get_s_node();
   const net_node_list_item* orig_t_node = orig.get_t_node();

   // copy member node lists one by one
   src_nodes = copy_node_list(orig_src_nodes);
   dst_nodes = copy_node_list(orig_dst_nodes);
   s_node = copy_node_list(orig_s_node);
   t_node = copy_node_list(orig_t_node);

   // set pointers to neighbour nodes
   set_destination_nodes(orig_t_node, t_node, dst_nodes, NULL);
   set_destination_nodes(orig_dst_nodes, dst_nodes, src_nodes, t_node);
   set_destination_nodes(orig_src_nodes, src_nodes, s_node, dst_nodes);
   set_destination_nodes(orig_s_node, s_node, NULL, src_nodes);
} // end Filter_graph()


/*
 * Copy assignment.
 */
Flow_network& Flow_network::operator=(const Flow_network& copy) {
   // destruct the original object
   remove_node_list(s_node);
   remove_node_list(src_nodes);
   remove_node_list(dst_nodes);
   remove_node_list(t_node);

   // acquire members of the copied object
   const net_node_list_item* copy_src_nodes = copy.get_src_nodes();
   const net_node_list_item* copy_dst_nodes = copy.get_dst_nodes();
   const net_node_list_item* copy_s_node = copy.get_s_node();
   const net_node_list_item* copy_t_node = copy.get_t_node();

   // copy member node lists one by one
   src_nodes = copy_node_list(copy_src_nodes);
   dst_nodes = copy_node_list(copy_dst_nodes);
   s_node = copy_node_list(copy_s_node);
   t_node = copy_node_list(copy_t_node);

   // set pointers to neighbour nodes
   set_destination_nodes(copy_t_node, t_node, dst_nodes, NULL);
   set_destination_nodes(copy_dst_nodes, dst_nodes, src_nodes, t_node);
   set_destination_nodes(copy_src_nodes, src_nodes, s_node, dst_nodes);
   set_destination_nodes(copy_s_node, s_node, NULL, src_nodes);

   // return the original object with new content
   return *this;
} // end operator=()


/*
 * Destructor.
 */
Flow_network::~Flow_network() {
   remove_node_list(s_node);
   remove_node_list(src_nodes);
   remove_node_list(dst_nodes);
   remove_node_list(t_node);
} // end ~Flow_network()


/*
 * Adds an edge to the flow network.
 */
void Flow_network::add_edge(const IP_prefix& src_prefix, int src_list,
                            const IP_prefix& dst_prefix, int dst_list,
                            neighbour_list_item* orig_edge, bool forward_edge,
                            int capacity) {
   // get pointer to correct source node list pointer
   net_node_list_item** src_list_ptr;
   switch (src_list) {
      case 0 :
         src_list_ptr = &s_node;
         break;
      case 1 :
         src_list_ptr = &src_nodes;
         break;
      case 2 :
         src_list_ptr = &dst_nodes;
         break;
      case 3 :
         src_list_ptr = &t_node;
         break;
   }

   // get pointer to correct destination node list pointer
   net_node_list_item** dst_list_ptr;
   switch (dst_list) {
      case 0 :
         dst_list_ptr = &s_node;
         break;
      case 1 :
         dst_list_ptr = &src_nodes;
         break;
      case 2 :
         dst_list_ptr = &dst_nodes;
         break;
      case 3 :
         dst_list_ptr = &t_node;
         break;
   }

   // find source prefix node in the specified node list and insert such node
   // if it does not exist
   net_node_list_item* src_node = find_node(src_prefix, *src_list_ptr);
   if (src_node == NULL) {
      // node is inserted at the beginning of the list
      insert_node(src_prefix, src_list_ptr);
      src_node = *src_list_ptr;
   }

   // find destination prefix node in the specified node list and insert such node
   // if it does not exist
   net_node_list_item* dst_node = find_node(dst_prefix, *dst_list_ptr);
   if (dst_node == NULL) {
      // node is inserted at the beginning of the list
      insert_node(dst_prefix, dst_list_ptr);
      dst_node = *dst_list_ptr;
   }

   // find neighbour node corresponding to the filter and insert such node if
   // it does not exist
   net_neighbour_list_item* neighbour = find_neighbour(dst_node,
                                                       src_node->neighbours);
   if (neighbour == NULL) {
      // neighbour is inserted at the beginning of the list
      insert_neighbour(src_node, dst_node, capacity, 0, orig_edge,
                       forward_edge, &(src_node->neighbours));
   }
} // end add_edge()


/*
 * Transforms the flow network into a level graph.
 */
void Flow_network::to_level_graph() {

   // initialize auxiliary variables
   queue<net_node_list_item*> q;
   stack<net_neighbour_list_item**> s;
   if (s_node != NULL) {
      s_node->visited = true;
      q.push(s_node);
   }

   // do a breadth-first search
   while (!q.empty()) {
      // dequeue the front element of the queue
      net_node_list_item* node = q.front();
      q.pop();
      // iterate through the list of node's neighbours
      net_neighbour_list_item** neighbour_ptr = &(node->neighbours);
      while ((*neighbour_ptr) != NULL) {
         // push a pointer to a pointer to the edge on the stack
         s.push(neighbour_ptr);
         // if it has not been visited yet, enqueue a pointer to the target
         // node of this edge
         if ((*neighbour_ptr)->dst_node->visited == false) {
            (*neighbour_ptr)->dst_node->visited = true;
            q.push((*neighbour_ptr)->dst_node);
         }
         // move to the next neighbour
         neighbour_ptr = &((*neighbour_ptr)->next);
      }
   }

   // initialize a set of level graph nodes with the 't' node
   list<net_node_list_item*> l;
   l.push_front(t_node);

   // do an inverse breadth-first search
   while (!s.empty()) {
      // pop the top element of the stack
      net_neighbour_list_item** neighbour_ptr = s.top();
      s.pop();
      // check if the dst_node already belongs to the level graph
      net_node_list_item* dst_node = (*neighbour_ptr)->dst_node;
      list<net_node_list_item*>::iterator i;
      for (i = l.begin(); i != l.end(); ++i) {
         if (*i == dst_node) {
            break;
         }
      }
      if (i != l.end()) { // dst_node belongs to the level graph
         // add also src_node to the level graph
         l.push_front((*neighbour_ptr)->src_node);
      } else { // dst_node does not belong to the level graph
         // remove the edge from the flow network
         net_neighbour_list_item* edge = (*neighbour_ptr);
         *neighbour_ptr = (*neighbour_ptr)->next;
         delete edge;
      }
   }
} // end to_level_graph()


/*
 * Finds a blocking flow in the flow network, adds its value to the
 * current flow in the corresponding filter graph, and also returns its
 * value.
 */
int Flow_network::find_blocking_flow() {
   // check if the flow network exists at all
   if (s_node == NULL) {
      return 0;
   }

   int blocking_flow = 0;
   while (1) { // inifinite loop with return statement inside
      // initialize auxiliary variables
      stack<net_neighbour_list_item**> s;
      stack<int> s_capacity;
      net_node_list_item* node = s_node;
      // do a depth-first search
      while (node != t_node) {
         while (node->neighbours == NULL) { // no output edges - traverse back
            if (s.empty()) { // the stack is empty - no way to traverse back
               return blocking_flow;
            }
            // traverse back along the edge on the top of the stack
            net_neighbour_list_item** neighbour_ptr = s.top();
            net_neighbour_list_item* neighbour = *neighbour_ptr;
            node = neighbour->src_node;
            // pop the top elements of both stacks
            s.pop();
            s_capacity.pop();
            // remove back-traversed edge
            *neighbour_ptr = neighbour->next;
            delete neighbour;
         }
         // push the first edge of the current node and its remaining capacity on
         // the respective stacks
         s.push(&(node->neighbours));
         s_capacity.push(node->neighbours->capacity - node->neighbours->flow);
         // move forward along the edge - update the current node
         node = node->neighbours->dst_node;
      }

      // determine the smallest capacity among edges of the found path
      int min_capacity = s_capacity.top();
      s_capacity.pop();
      while (!s_capacity.empty()) {
         // pop the top element of the capacity stack
         int capacity = s_capacity.top();
         s_capacity.pop();
         if (capacity < min_capacity) { // update the smallest capacity
            min_capacity = capacity;
         }
      }

      // update the flow through the found path according to min_capacity value
      while (!s.empty()) {
         // pop the top element of the stack
         net_neighbour_list_item** neighbour_ptr = s.top();
         s.pop();
         // update the flow in both the flow network and filter graph
         net_neighbour_list_item* neighbour = *neighbour_ptr;
         neighbour->flow += min_capacity;
         if (neighbour->forward_edge) { // forward edge
            neighbour->orig_edge->flow += min_capacity;
         } else { // backward edge
            neighbour->orig_edge->flow -= min_capacity;
         }
         // remove the edge if its remaining capacity decreases to 0
         if (neighbour->capacity == neighbour->flow) {
            *neighbour_ptr = neighbour->next;
            delete neighbour;
         }
      }

      // update the value of blocking flow through the flow network
      blocking_flow += min_capacity;
   }
} // end find_blocking_flow()


/*
 * Prints the flow network.
 */
void Flow_network::print() {
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
