// filter_graph.h: header file for Filter_graph class
//
// Jiri Matousek, 2017
// imatousek@fit.vutbr.cz


#ifndef FILTER_GRAPH_H
#define FILTER_GRAPH_H


// User includes
#include "ip_prefix.h"

// Library includes

// Default namespace
using namespace std;


// ****************************************************************************
//                            Structures declaration
// ****************************************************************************


// Forward declarations (including typedef) to resolve circular dependency
typedef struct node_list_item node_list_item;
typedef struct neighbour_list_item neighbour_list_item;
typedef struct filter_list_item filter_list_item;

/*
 * A structure representing an item in a list of graph nodes.
 */
struct node_list_item {
   // IP prefix represented by this node
   IP_prefix prefix;

   // Flag that is utilized for "pruning" filters once the complete filter
   // graph is constructed
   bool pruned;

   // List of neighbours
   neighbour_list_item* neighbours;

   // Next item in list of graph nodes
   node_list_item* next;
};

/*
 * A structure representing an item in a list of neighbours of a graph node.
 */
struct neighbour_list_item {
   // Pointer to neighbour node within list of graph nodes
   node_list_item* node;

   // Weight of filter graph's edge between neighbouring nodes
   int weight;

   // Flow through filter graph's edge between neighbouring nodes
   int flow;

   // List of filters that specify prefixes of neighbouring nodes
   filter_list_item* filters;

   // Next item in list of neighbours
   neighbour_list_item* next;
};

/*
 * A Structure representing an item in a list of filters that specify prefixes
 * of neighbouring graph nodes.
 */
struct filter_list_item {
   // Pointer to representation of filter
   // (struct filter is defined in stdinc.h included in custom_db.cc)
   const struct filter* filter;

   // Next item in list of filters
   filter_list_item* next;
};


// ****************************************************************************
//                              Class declaration
// ****************************************************************************

/*
 * Class for representation of a set of filters as a filter graph -- i.e.,
 * weighted directed bipartite graph with special source (s) and terminate (t)
 * nodes -- that is constructed according to filters' source and destination
 * prefixes and pruned source and destination prefix tries.
 */
class Filter_graph {


   // ***** Private members ***************************************************


   private:
      /*
       * Lists of source and destination nodes of the filter graph.
       */
      node_list_item* src_nodes;
      node_list_item* dst_nodes;

      /*
       * Special nodes 's' and 't' of the filter graph.
       */
      node_list_item* s_node;
      node_list_item* t_node;

      /*
       * Private static function that creates deep copy of the original list.
       * The function creates new instances of all items from the original list
       * (as well as all sublists) and sets the value of their components
       * according to this original list. The only exception is pointer to
       * neighbour node, which is initialized to NULL (it points to different
       * list, thus it cannot be initialized to correct value during copying).
       * @param orig   Pointer to the constant original node list.
       * @return       Pointer to the copy of the original node list.
       */
      static node_list_item* copy_node_list(const node_list_item* orig);

      /*
       * Private static function that correctly deallocates the whole node
       * list.
       * The function traverses the given node list and all its sublists and
       * starting from the inner-most list it deallocates all the traversed
       * list items.
       * @ param list   Pointer to pointer to node list that is to be
       *                deallocated.
       */
      static void remove_node_list(node_list_item** list);

      /*
       * Private static function that correctly deallocates the whole neighbour
       * list.
       * The function traverses the given neighbour list and all its sublists
       * and starting from the inner-most list it deallocates all the traversed
       * list items.
       * @param   Pointer to pointer to the neighbour list that is to be
       *          deallocated.
       */
      static void remove_neighbour_list(neighbour_list_item** list);

      /*
       * Private static function that correctly deallocates the whole filter
       * list.
       * The function traverses the given filter list and deallocates all the
       * traversed list items.
       * @param   Pointer to pointer to the filter list that is to be
       *          deallocated.
       */
      static void remove_filter_list(filter_list_item** list);

      /*
       * Private static function that sets correct values of neighbour node
       * pointers, which cannot be correctly initialized during copying.
       * The function simultaneously traverses neighbours lists in orig and src
       * node lists. For each neighbour node from orig list it looks for
       * corresponding item in dst node list and stores pointer to this node to
       * current item in src list.
       * @param orig   Pointer to the constant original node list.
       * @param src    Pointer to the list of source nodes (neighbour node
       *               pointers of this list are set).
       * @param dst    Pointer to the list of destination nodes (nodes of this
       *               list act as targets of neighbour node pointers within
       *               src node list).
       */
      static void set_neighbour_nodes(const node_list_item* orig,
                                            node_list_item* src,
                                            node_list_item* dst);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function that looks for node with the given prefix in
       * the given list of nodes.
       * @param prefix   Reference to a constant IP prefix of node that the
       *                 function looks for in the list.
       * @param list     Pointer to list of nodes that is traversed during
       *                 looking for node with the given IP prefix.
       * @return         Pointer to found node or NULL.
       */
      static node_list_item* find_node(const IP_prefix& prefix,
                                             node_list_item* list);

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
      static neighbour_list_item* find_neighbour(
                                     const node_list_item* neighbour,
                                     neighbour_list_item* list);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function that looks for the filter node pointing to the
       * specified filter in the given list of filters.
       * @param filter   Pointer to the constant filter that is referenced by
       *                 the filter node the function looks for in the list.
       * @param list     Pointer to the list of filter nodes that is traversed
       *                 during looking for a node pointing to the given
       *                 filter.
       * @return         Pointer to the found filter node or NULL.
       */
      static filter_list_item* find_filter(const struct filter* filter,
                                           filter_list_item* list);

      /*
       * Private static function that inserts a node representing the given IP
       * prefix at the beginning of the given list of nodes.
       * @param prefix   Reference to a constant IP prefix that is going to be
       *                 represented by the inserted node.
       * @param list     Pointer to pointer to the list of nodes that is going
       *                 to be extended by the inserted node.
       */
      static void insert_node(const IP_prefix& prefix,
                              node_list_item** list);

      /*
       * Private static function that inserts a neighbour node corresponding to
       * the given prefix node at the beginning of the given list of
       * neighbour nodes.
       * @param neighbour   Pointer to a prefix node whose neighbour node is
       *                    going to be inserted.
       * @param list        Pointer to pointer to the list of neighbours that
       *                    is going to be extended by the inserted node.
       */
      static void insert_neighbour(node_list_item* neighbour,
                                   neighbour_list_item** list);

      /*
       * Private static function that inserts a filter node pointing to the
       * given filter at the beginning of the given list of filter nodes.
       * @param node   Pointer to the constant filter that is going to be
       *               referenced by the inserted filter node.
       * @param list   Pointer to pointer to the list of filters that is going
       *               to be extended by the inserted node.
       */
      static void insert_filter(const struct filter* filter,
                                filter_list_item** list);

      /*
       * Private static function that prints specified node list, including all
       * sublists (i.e., neighbour lists and filter lists).
       * @param nodes   Pointer to the constant list of nodes that is to be
       *                printed.
       */
      static void print_node_list(const node_list_item* nodes);

      /*
       * Private function that removes non-pruned nodes and resets the "pruned"
       * flag of pruned nodes of the filter graph.
       * The function performs the specified function on all nodes of the
       * filter graph (i.e., source and destination nodes as well as the 's'
       * and 't' nodes).
       * The function expects that neighbours list referenced from the
       * non-pruned nodes have been correctly deallocated before calling this
       * function.
       */
      void remove_and_reset();


   // ***** Public members ****************************************************


   public:
      /*
       * Default constructor.
       * All pointers are initialized to NULL.
       */
      Filter_graph();

      /*
       * Copy constructor.
       * All pointers are initialized to a deep copy of corresponding members
       * of the original object.
       * @param orig   Reference to the constant original object.
       */
      Filter_graph(const Filter_graph& orig);

      /*
       * Destructor.
       * Correctly deallocates all lists that are referenced by object members.
       */
      ~Filter_graph();

      /*
       * Copy assignment.
       * The original object is destructed and its new content is constructed
       * in similar way as in the copy constructor.
       * @param copy   Reference to the constant copied object.
       * @return       Reference to the original object with new content.
       */
      Filter_graph& operator= (const Filter_graph& copy);

      /*
       * Get function for the src_nodes member.
       * @return   Pointer to the constant list of source nodes.
       */
      inline const node_list_item* get_src_nodes() const {
         return src_nodes;
      } // end get_src_nodes()

      /*
       * Get function for the dst_nodes member.
       * @return   Pointer to the constant list of destination nodes.
       */
      inline const node_list_item* get_dst_nodes() const {
         return dst_nodes;
      } // end get_dst_nodes()

      /*
       * Get function for the s_node member.
       * @return   Pointer to the constant special 's' node.
       */
      inline const node_list_item* get_s_node() const {
         return s_node;
      } // end get_s_node()

      /*
       * Get function for the t_node member.
       * @return   Pointer to the constant special 't' node.
       */
      inline const node_list_item* get_t_node() const {
         return t_node;
      } // end get_t_node()

      /*
       * Modifies filter graph to add the specified filter into the set of
       * filters represented by the graph.
       * The function searches src_nodes and dst_nodes lists for nodes
       * representing source and destination prefixes of the given filter and
       * inserts such nodes into these lists if they are not found. Next, the
       * function seraches neighbours list of source prefix node for neighbour
       * node representing destination prefix of the given filter and inserts
       * such neighbour node into the list if it is not found. Finally, the
       * function searches filters list of neighbouring node for pointer to the
       * given filter and inserts such pointer into the list if it is not
       * found. Along with inserting new filter pointer to the list, the
       * function increments weight item of neighbouring node representation.
       * @param filter   Pointer to a constant structure representing inserted
       *                 filter.
       */
      void add_filter(const struct filter* filter);

      /*
       * Adds an edge from the 's' node to a node representing the given prefix
       * within the source nodes list and sets its weight to the given value.
       * First of all, the function checks whether the 's' node has already
       * been allocated and allocates this node in case it does not yet exist.
       * Next, the function searches the neighbours list of the 's' node for a
       * neighbour node representing the given prefix. If such neighbour node
       * exists, the function just adds the given weight to the current value
       * of its weight counter. If such neighbour node does not exist, the
       * function inserts the node into the list and sets its weight counter to
       * the given value. The function also sets the "pruned" flag of the node
       * representing the given prefix to true.
       * The implementation expects that all filters have already been added to
       * the filter graph and that only prefixes of a pruned source trie are
       * added using this function. In such a case the source nodes list always
       * contains a node representing the given prefix.
       * @param prefix   Reference to the IP_prefix object that determines a
       *                 target node of the edge from the 's' node.
       * @param weight   Weight of the newly created edge.
       */
      void add_s_prefix(const IP_prefix& prefix, const int weight);

      /*
       * Adds an edge from a node representing the given prefix within the
       * destination nodes list to the 't' node and sets its weight to the
       * given value.
       * First of all, the function checks whether the 't' node has already
       * been allocated and allocates this node in case it does not yet exist.
       * Next, the function searches the neighbours list of the node
       * representing the given prefix within the destination nodes list for a
       * neighbour node representing the 't' node. If such neighbour node
       * exists, the function just adds the given weight to the current value
       * of its weight counter. If such neighbour node does not exist, the
       * function inserts the node into the list and sets its weight counter to
       * the given value. The function also sets the "pruned" flag of the node
       * representing the given prefix to true.
       * The implementation expects that all filters have already been added to
       * the filter graph and that only prefixes of a pruned destination trie
       * are added using this function. In such a case the destination nodes
       * list always contains a node representing the given prefix.
       * @param prefix   Reference to the IP_prefix object that determines a
       *                 source node of the edge towards the 't' node.
       * @param weight   Weight of the newly created edge.
       */
      void add_t_prefix(const IP_prefix& prefix, const int weight);

      /*
       * Modifies the filter graph such that it conforms with the flow network
       * specification -- i.e., it has only one node without input edges (the
       * 's' node) and only one node without output edges (the 't' node).
       * First of all, the function removes all edges representing filters with
       * at least one non-pruned prefix and all nodes representing non-pruned
       * prefixes. During this step, the "pruned" flag of the remaining nodes
       * is also set to false. Next, the filter graph is traversed in a BFS
       * manner and the "pruned" flag is set to true for all visited nodes with
       * at least one input edge and one output edge. Finally, the function
       * removes all edges going from the 's' node/to the 't' node that do not
       * end/start in a node with the set "pruned" flag. These non-pruned nodes
       * are also removed from the graph in this final step.
       * The function expects that all steps of the filter graph construction
       * (i.e., adding filters, s-prefixes, and t-prefixes) have already been
       * performed before its invocation.
       */
      void to_flow_network();

      /*
       * Computes maximum flow using Dinic's algorithm.
       * The function builds a flow network corresponding to the filter graph,
       * transforms it to a level graph and updates the flow through the filter
       * graph according to a blocking flow through the level graph. This way
       * the flow through the filter graph is iteratively updated until there
       * are paths from the 's' node to the 't' node in the level graph.
       * The flow network is represented by an object of the Flow_network,
       * which also allows transformation into the corresponding level graph.
       * @return   The value of the maximum flow through the filter graph.
       */
      int max_flow();

      /*
       * Prints the filter graph.
       */
      void print();
};

#endif
