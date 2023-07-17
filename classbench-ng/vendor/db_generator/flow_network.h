// flow_network.h: header file for Flow_network class
//
// Jiri Matousek, 2017
// imatousek@fit.vutbr.cz


#ifndef FLOW_NETWORK_H
#define FLOW_NETWORK_H


// User includes
#include "ip_prefix.h"
#include "filter_graph.h"

// Library includes

// Default namespace
using namespace std;


// ****************************************************************************
//                            Structures declaration
// ****************************************************************************


// Forward declarations (including typedef) to resolve circular dependency
typedef struct net_node_list_item net_node_list_item;
typedef struct net_neighbour_list_item net_neighbour_list_item;

/*
 * A structure representing an item in a list of network nodes.
 */
struct net_node_list_item {
   // IP prefix represented by this node
   IP_prefix prefix;

   // Flag showing whether the node was already visited during a traversal
   bool visited;

   // List of neighbours
   net_neighbour_list_item* neighbours;

   // Next item in list of network nodes
   net_node_list_item* next;
};

/*
 * A structure representing an item in a list of neighbours of a network node.
 */
struct net_neighbour_list_item {
   // Pointer to source node within list of network nodes
   net_node_list_item* src_node;

   // Pointer to destination node within list of network nodes
   net_node_list_item* dst_node;

   // Residual capacity of flow network's edge between neighbouring nodes
   int capacity;

   // Flow through flow network's edge between neighbouring nodes
   int flow;

   // Pointer to corresponding edge in filter graph
   // (the pointer is the same for both forward and backward edges)
   neighbour_list_item* orig_edge;

   // Flag showing whether this node represents a forward edge
   bool forward_edge;

   // Next item in list of neighbours
   net_neighbour_list_item* next;
};


// ****************************************************************************
//                              Class declaration
// ****************************************************************************

/*
 * Class for representation of a flow network -- i.e., weighted directed graph
 * with special source (s) and terminate (t) nodes -- over a filter graph.
 */
class Flow_network {


   // ***** Private members ***************************************************


   private:
      /*
       * Lists of source and destination nodes of the flow network.
       */
      net_node_list_item* src_nodes;
      net_node_list_item* dst_nodes;

      /*
       * Special nodes 's' and 't' of the flow network.
       */
      net_node_list_item* s_node;
      net_node_list_item* t_node;

      /*
       * Private static function that creates a deep copy of the original list.
       * The function creates new instances of all items from the original list
       * (as well as their neighbours sublists) and sets the value of their
       * components according to this original list. The only exception is a
       * pointer to destination node, which is initialized to NULL (it points
       * to different list, thus it cannot be initialized to correct value
       * during copying).
       * @param orig   Pointer to the constant original node list.
       * @return       Pointer to the copy of the original node list.
       */
      static net_node_list_item* copy_node_list(const net_node_list_item* orig);

      /*
       * Private static function that correctly deallocates the whole node
       * list.
       * The function traverses the given list and all its sublists and
       * starting from lists of neighbours it deallocates all the traversed
       * list items.
       * @ param list   Pointer to node list that is to be deallocated.
       */
      static void remove_node_list(net_node_list_item* list);

      /*
       * Private static function that sets correct values of destination node
       * pointers, which cannot be correctly initialized during copying.
       * The function simultaneously traverses neighbours lists in the orig and
       * copy node lists. For each destination node from the orig list it looks
       * for a corresponding item in either prev (backward edges) or next
       * (forward edges) node list and stores the pointer to this node to the
       * current item in the copy list.
       * @param orig   Pointer to the constant original node list.
       * @param copy   Pointer to the copy of the original node list
       *               (destination node pointers of this list are set).
       * @param prev   Pointer to the list of destination nodes of backward
       *               edges.
       * @param next   Pointer to the list of destination nodes of forward
       *               edges.
       */
      static void set_destination_nodes(const net_node_list_item* orig,
                                              net_node_list_item* copy,
                                              net_node_list_item* prev,
                                              net_node_list_item* next);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function that looks for a node with the given prefix in
       * the given list of nodes.
       * @param prefix   Reference to a constant IP prefix of the node that the
       *                 function looks for in the list.
       * @param list     Pointer to the list of nodes that is traversed during
       *                 looking for the node with the given IP prefix.
       * @return         Pointer to the found node or NULL.
       */
      static net_node_list_item* find_node(const IP_prefix& prefix,
                                                 net_node_list_item* list);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function that looks for the corresponding neighbour
       * node in the given list of neighbours.
       * @param neighbour   Pointer to a constant prefix node whose neighbour
       *                    node the function looks for in the list.
       * @param list        Pointer to the list of neighbour nodes that is
       *                    traversed during looking for the node corresponding
       *                    to the given prefix node.
       * @return            Pointer to the found neighbour node or NULL.
       */
      static net_neighbour_list_item* find_neighbour(
                                         const net_node_list_item* neighbour,
                                         net_neighbour_list_item* list);

      /*
       * Private static function that inserts a node representing the given IP
       * prefix at the beginning of the given list of nodes.
       * @param prefix   Reference to a constant IP prefix that is going to be
       *                 represented by the inserted node.
       * @param list     Pointer to pointer to the list of nodes that is going
       *                 to be extended by the inserted node.
       */
      static void insert_node(const IP_prefix& prefix,
                              net_node_list_item** list);

      /*
       * Private static function that inserts a neighbour node representing an
       * edge between the given source and destination nodes at the beginning
       * of the specified list of neighbour nodes.
       * @param src_node       Pointer to a source node of the represented
       *                       edge.
       * @param dst_node       Pointer to a destination node of the represented
       *                       edge.
       * @param capacity       Residual capacity of the represented edge.
       * @param flow           Flow through the represented edge.
       * @param orig_edge      Pointer to the corresponding edge in the filter
       *                       graph.
       * @param forward_edge   Flag showing whether the inserted neighbour
       *                       represents a forward edge.
       * @param list           Pointer to pointer to the list of neighbours
       *                       that is going to be extended by the inserted
       *                       node.
       */
      static void insert_neighbour(net_node_list_item* src_node,
                                   net_node_list_item* dst_node,
                                   int capacity,
                                   int flow,
                                   neighbour_list_item* orig_edge,
                                   bool forward_edge,
                                   net_neighbour_list_item** list);

      /*
       * Private static function that prints specified node list, including all
       * sublists.
       * @param nodes   Pointer to the constant list of nodes that is to be
       *                printed.
       */
      static void print_node_list(const net_node_list_item* nodes);


   // ***** Public members ****************************************************


   public:
      /*
       * Default constructor.
       * All pointers are initialized to NULL.
       */
      Flow_network();

      /*
       * Copy constructor.
       * All pointers used by the filter graph are initialized to a deep copy
       * of corresponding members of the original object.
       * @param orig   Reference to the constant original object.
       */
      Flow_network(const Flow_network& orig);

      /*
       * Copy assignment.
       * The original object is destructed and its new content is constructed
       * in a similar way as in the copy constructor.
       * @param copy   Reference to the constant copied object.
       * @return       Reference to the original object with new content.
       */
      Flow_network& operator= (const Flow_network& copy);

      /*
       * Destructor.
       * Correctly deallocates all lists that are referenced by object members.
       */
      ~Flow_network();

      /*
       * Get function for the src_nodes member.
       * @return   Pointer to the constant list of source nodes.
       */
      inline const net_node_list_item* get_src_nodes() const {
         return src_nodes;
      } // end get_src_nodes()

      /*
       * Get function for the dst_nodes member.
       * @return   Pointer to the constant list of destination nodes.
       */
      inline const net_node_list_item* get_dst_nodes() const {
         return dst_nodes;
      } // end get_dst_nodes()

      /*
       * Get function for the s_node member.
       * @return   Pointer to the constant special 's' node.
       */
      inline const net_node_list_item* get_s_node() const {
         return s_node;
      } // end get_s_node()

      /*
       * Get function for the t_node member.
       * @return   Pointer to the constant special 't' node.
       */
      inline const net_node_list_item* get_t_node() const {
         return t_node;
      } // end get_t_node()

      /*
       * Adds an edge to the flow network.
       * First of all, if they are not already present, the function inserts
       * nodes representing src_prefix and dst_prefix into node lists src_list
       * and dst_list, respectively. Next, if it is not already present, the
       * function inserts a neighbour node representing the edge into the list
       * of neighbours of the node representing the source prefix. Flow item of
       * the neighbour node is set to 0, while other items within its structure
       * are set according to the function's parameters.
       * @param src_prefix     Reference to the IP_prefix object that
       *                       determines a source node of the added edge.
       * @param src_list       Specification of a node list that contains the
       *                       source node of the added edge. Mapping of the
       *                       four allowed values to the node lists is the
       *                       following:
       *                          0 ... s_node
       *                          1 ... src_node
       *                          2 ... dst_node
       *                          3 ... t_node
       * @param dst_prefix     Reference to the IP_prefix object that
       *                       determines a destination node of the added edge.
       * @param dst_list       Specification of a node list that contains the
       *                       destination node of the added edge. Mapping of
       *                       the four allowed values to the node lists is the
       *                       following:
       *                          0 ... s_node
       *                          1 ... src_node
       *                          2 ... dst_node
       *                          3 ... t_node
       * @param orig_edge      Pointer to the corresponding edge in the filter
       *                       graph.
       * @param forward_edge   Flag showing whether the added edge represents a
       *                       forward edge.
       * @param capacity       Residual capacity of the added edge.
       */
      void add_edge(const IP_prefix& src_prefix, int src_list,
                    const IP_prefix& dst_prefix, int dst_list,
                    neighbour_list_item* orig_edge, bool forward_edge,
                    int capacity);

      /*
       * Transforms the flow network into a level graph.
       * During inverse BFS of the flow network, starting from a set containing
       * the 't' node, the function incrementally extends the set by start
       * nodes of edges ending in one of the set nodes and removes from the
       * flow network edges that do not meet this condition.
       */
      void to_level_graph();

      /*
       * Finds a blocking flow in the flow network, adds its value to the
       * current flow in the corresponding filter graph, and also returns its
       * value.
       * The function repeatedly performs DST to find an s-t path in the flow
       * network and the smallest capacity on this path. Once the function
       * reaches the 't' node, it returns along the found path and increases
       * the flow through the particular flow network edges as well as the
       * corresponding filter graph edges. The function also updates capacities
       * of backward-traversed flow network edges and removes them in case
       * their capacity decreases to 0. In case of DFS ending in a node other
       * than the 't' node, the function traverses back to the closest node
       * with at least two output edges and removes all back-traversed edges.
       * After each successful DFS and flow update on the found path, the
       * function increases the value of the total flow through the flow
       * network, which is returned at the end.
       * The function expects that the flow network is in the form of a level
       * graph at the time of invocation.
       * @return   The value of the blocking flow through the flow network.
       */
      int find_blocking_flow();

      /*
       * Prints the flow network.
       */
      void print();
};

#endif
