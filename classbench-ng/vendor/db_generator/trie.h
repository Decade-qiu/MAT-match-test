// trie.h: header file for trie class
//
// Jiri Matousek, 2014
// imatousek@fit.vutbr.cz


#ifndef TRIE_H
#define TRIE_H


// User includes
#include "ip_prefix.h"

// Library includes
#include <vector>
#include <queue>

// Default namespace
using namespace std;


// ****************************************************************************
//                            Structures declaration
// ****************************************************************************

/*
 * Structure representing a node of a trie.
 *
 * Each node can be a prefix node (prefixes > 0) or a non-prefix node
 * (prefixes = 0) and it can have at most two successors accessible using
 * pointers zero (when the next bit of the prefix is 0) or one (when the next
 * bit of the prefix is 1).
 * Except these basic members, each trie node stores some other values that
 * make the computation of trie characteristics easier. These values are
 * further described directly in the trie node structure declaration.
 */

struct trie_node {
   // trie level (i.e. distance from the root) at which the node resides
   int level;

   // number of occurences of the prefix
   int prefixes;

   // counter of branches with maximum prefix nesting that this node is part of
   int prefix_nesting_branches;

   // 0-subtree-related members
   trie_node* zero; // pointer to the subtree root
   int zero_weight; // number of prefixes in the subtree

   // 1-subtree-related members
   trie_node* one; // pointer to the subtree root
   int one_weight; // number of prefixes in the subtree
};

/*
 * Structure representing trie statistics proposed in the ClassBench tool.
 *
 * Vector members store statistics defined separately for each level of the
 * trie. Prefix nesting is defined for the whole trie.
 */
struct classbench_stats {
   // total number of prefixes
   int prefixes;

   // number of prefixes (not prefix nodes) with given length
   vector<int> prefix_lengths;

   // probability of node with only one child (from all non-leaf nodes)
   vector<float> branching_one_child;
   // probability of node with two children (from all non-leaf nodes)
   vector<float> branching_two_children;

   // average relative weight ratio of lighter vs heavier subtree
   // (nodes with two children only)
   vector<float> skew;

   // maximum number of prefix nodes on an arbitrary path in the trie
   int prefix_nesting;
};

/*
 * Structure representing statistics related to trie nodes.
 *
 * All the statistics are stored separately for each level of the trie.
 */
struct node_stats {
   vector<int> leaf;         // number of leaf nodes
   vector<int> one_child;    // number of nodes with one child only
   vector<int> two_children; // number of nodes with both children
   vector<int> prefix;       // number of prefix nodes (not prefixes)
   vector<int> non_prefix;   // number of non-prefix nodes
};

/*
 * Structure representing statistics related to the trie.
 *
 * Statistics are divided into two groups:
 *    1) statistics proposed in ClassBench tool and
 *    2) statistics related to trie nodes.
 */
struct trie_stats {
   classbench_stats classbench; // ClassBench statistics
   node_stats nodes;            // nodes statistics
};

// ****************************************************************************
//                              Class declaration
// ****************************************************************************

/*
 * Class for representation of a binary prefix tree - trie.
 *
 * Class functions do not adjust zero_weight and one_weight counters in a trie
 * node by default. These feilds are viewed as place holders and they can be
 * set to the correct value by calling the compute_weights().
 */
class Trie {
   private:
      /*
       * Pointer to the root node of the trie.
       */
      trie_node* root;

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
// (MAYBE JUST ONE REASON -- BY COPYING ONLY A SUBTREE YOU LOOSE THE
// INFORMATION ABOUT THE COMMON PREFIX, I.E. PATH IN TRIE PRECEDING THIS
// SUBTREE)
      /*
       * Private static function for copying a subtree of the trie, where the
       * subtree is specified by a pointer to its root node.
       * Trie node members prefixes, zero_weight, and one_weight are copied
       * without any change, while the level member is set to the given value.
       * This approach allows e.g. to create a new valid trie by copying the
       * given subtree. (In such a case the level parameter have to be set to
       * 0 during the initial function call.)
       * Trie node members zero and one are set to the values returned by the
       * recursive call of the copy() onto the 0-subtree and 1-subtree,
       * respectively.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node    Pointer to the root node of a subtree that is to be
       *                copied.
       * @param level   Value for the level member of the copied trie node.
       * @return        Pointer to the root node of the copy.
       */
      static trie_node* copy(const trie_node* node, int level);

      /*
       * Private static function for destruction of a trie's subtree. The
       * subtree is given by a pointer to its root node.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node   Pointer to the root node of a subtree that is to be
       *               destructed.
       */
      static void destruct(trie_node* node);

      /*
       * Private static function for computation of zero_weight and one_weight
       * values of all the trie nodes in a given subtree. The subtree is given
       * by a pointer to its root node.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node   Pointer to the root node of the subtree in which the
       *               weights are to be computed.
       * @return       Weights of the given subtree.
       */
      static int compute_weights(trie_node* node);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function for computation of node's skew as defined in
       * the ClassBench paper. This function expects that the pointed node is
       * a 2-children node and that its fields zero_weight and one_weight
       * contain valid values.
       * @param node   Pointer to the node of which the skew is going to be
       *               computed.
       * @return       Skew of the given node.
       */
      static float compute_skew(trie_node* node);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function that determines the maximum prefix nesting in
       * a given subtree, i.e. the maximum number of prefixes on any path from
       * the root to the leaves in the subtree. The subtree is given by a
       * pointer to its root node.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node    Pointer to the root node of the subtree in which the
       *                prefix nesting is to be computed.
       * @return        Maximum prefix nesting in the given subtree.
       */
      static int get_prefix_nesting(const trie_node* node);

      /*
       * Private static function that removes the lightest subtree among trie
       * nodes passed in a queue. The lightest subtree can be selected
       * either among one-child nodes or two-children nodes. The selection is
       * done in such a way that when the lightest subtree is removed, there
       * is still at least one branch with maximum prefix nesting in the trie.
       * After removing the lightest subtree, corresponding subtree weight is
       * set to 0.
       * @param q                         Queue with trie nodes that are to be
       *                                  inspected.
       * @param one_child                 Select lightest subtree either among
       *                                  one-child nodes (TRUE) or
       *                                  two-children nodes (FALSE).
       * @param prefix_nesting_branches   The number of branches in the trie
       *                                  with maximum prefix nesting.
       */
      static void remove_lightest_subtree(queue<trie_node*> q, bool one_child,
                                          int prefix_nesting_branches);

      /*
       * Private static function for marking branches with maximum prefix
       * nesting in a given subtree. The subtree is given by a pointer to its
       * root node. Maximum prefix nesting is specified as a parameter of the
       * function (therefore, it has to be computed outside the function).
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node             Pointer to the root node of the subtree in
       *                         which prefix nesting branches are to be
                                 marked.
       * @param prefix_nesting   Maximum prefix nesting in the given subtree.
       * @param seen_prefixes    Number of prefixes that has been seen so far.
       * @return                 Weights of the given subtree.
       */
      static int mark_prefix_nesting_branches(trie_node* node,
                                              int prefix_nesting,
                                              int seen_prefixes);

// PROBABLY IT IS NOT NECESSARY TO HAVE THIS FUNCTION PRIVATE
      /*
       * Private static function for computation of the maximum number of
       * prefixes that can be removed from a given subtree. When computing the
       * result of this function, the following contraints are taken into
       * account:
       *    * no prefix node within the subtree must not become a non-prefix
       *      node after removing the prefixes;
       *    * removing the prefixes from subtrees of 2-children node should not
       *      alter the skew of this node.
       * The subtree is given by a pointer to its root node.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node   A Pointer to the root node of the subtree in which the
                       number of removable prefixes is going to be computed.
       * @return       The number of removable prefixes in the given subtree.
       */
      static int get_removable_prefixes(trie_node* node);

      /*
       * Private static function for adjusting skew of a specified node to the
       * given value. The node is specified by it's pointer and the target
       * skew is given as a float number.
       * @param node          Pointer to the node whose skew is going to be
       *                      adjusted.
       * @param target_skew   The value to which the node's skew should be
       *                      adjusted.
       */
      static void adjust_node_skew(trie_node* node, float target_skew);

      /*
       * Private static function that removes the given number of prefixes from
       * a subtree specified by the pointer to its root node. Prefixes are
       * removed as equally as possible while following a rule that no prefix
       * node can be turned to a non-prefix node. Removing of prefixes is
       * performed over all prefix nodes from the root node up to the closest
       * 2-children node or a leaf node...
       * @param root        Pointer to the root node of the subtree in which
       *                    prefixes are going to be removed.
       * @remove_prefixes   The number of prefixes that should be removed from
       *                    the specified subtree.
       */
      static void make_subtree_lighter(trie_node* root, int remove_prefixes);

      /*
       * Private static function for removing branches without a prefix node
       * from a given subtree. The subtree is given by a pointer to its root
       * node.
       * CAUTION:
       *    * This function uses recursive calls!
       * @param node   Pointer to the root node of the subtree in which
       *               nonprefix are to be removed.
       * @return       actualized pointer to the subtree's root node
       *               (NULL when the whole subtree was removed)
       */
      static trie_node* remove_nonprefix_branches(trie_node* node);

      /*
       * Private function that removes some subtrees in order to achieve
       * branching probabilities that are as close as possible to the given
       * values.
       * Modifications are done on a per level basis, starting from the root
       * node. Changes at each level are done in two steps:
       *    1) lightest subtrees of two-children nodes are removed to achieve
       *       given branching_two_children probability
       *    2) lightest subtrees of one-child nodes are removed to achieve
       *       given branching_one_child probability
       * @param branching_one_child      Vector specifying probability of
       *                                 occurence of a trie node with one
       *                                 child at the given level of the trie.
       * @param branching_two_children   Vector specifying probability of
       *                                 occurence of a trie node with two
       *                                 children at the given level of the
       *                                 trie.
       */
      void adjust_branching(vector<float> branching_one_child,
                            vector<float> branching_two_children);

      /*
       * Private function that removes some prefixes in order to achieve an
       * average skew that is as close as possible to the given values for
       * particular levels.
       * Prefixes are removed on a per level basis, starting from the lowest
       * level. At each level, an average skew is increased/decreased by
       * removing prefixes from lighter/heavier subtree of the level's nodes.
       * This adjustment starts from nodes with the lightest subtrees
       * (adjusting their skew requires removing of the lowest number of
       * prefixes) and it is implemented such that it (almost) does not change
       * a skew of nodes at lower levels.
       * @param skew      Vector specifying an average skew at all levels of
       *                  the trie.
       * @ skew_epsilon   Threshold value for average skew change at not yet
       *                  adjusted nodes (skew adjustment stops when average
       *                  skew change is less than the given skew_epsilon).
       */
      void adjust_skew(vector<float> skew, float skew_epsilon = 0.01);

      /*
       * Private function that removes some prefixes in order to achieve
       * prefixes distribution that is as close as possible to the given values
       * for particular levels.
       * Prefixes are removed on a per level basis, starting from the root
       * node. Removing the prefixes consists of three steps:
       *    1) removing the prefixes from leaf nodes (the last prefix
       *       represented by a leaf node is never removed)
       *    2) removing the prefixes from non-leaf nodes, proportionally to
       *       their weight
       *    3) distributing prefixes that are to be removed at lower levels to
       *       subtrees of non-leaf nodes (this distribution is driven by skew)
       * @param prefixes_proportion   Vector that for all trie levels specifies
       *                              proportion of prefixes at the given level
       *                              to all prefixes in the trie.
       * @param target_size           Target total number of prefixes in the
       *                              trie.
       */
      void adjust_prefixes(vector<float> prefixes_proportion,
                           const int target_size);

   public:
      /*
       * Default constructor.
       * Pointer to the root node is initialized to NULL.
       */
      Trie();

      /*
       * Copy constructor.
       * Pointer to the root node is initialized by the result of the private
       * copy().
       * @param orig   Reference to the original trie object.
       */
      Trie(const Trie& orig);

      /*
       * Destructor.
       * Trie specified by the root pointer is destructed by the private
       * destruct().
       */
      ~Trie();

      /*
       * Copy assignment.
       * Original trie is destructed by the private destruct() and the new trie
       * is created by the private copy().
       * @param orig   Reference to the original trie object.
       * @return       Reference to the new trie object.
       */
      Trie& operator= (const Trie& orig);

      /*
       * Get function for the root pointer.
       * @return   Pointer to the root node of the trie.
       */
      inline const trie_node* get_root() const {
         return root;
      } // end get_root()

      /*
       * Inserts the specified prefix into the trie.
       * The trie is non-recursively traversed to the corresponding trie node,
       * where the prefix is newly inserted or at least the counter of its
       * occurences is incremented.
       * All the missing nodes on a way to the prefix node are newly created
       * and inserted into the trie as non-prefix nodes.
       * @param pref   Reference to the IP_prefix object representing the
       *               prefix that is to be inserted.
       */
      void insert(const IP_prefix& pref);

      /*
       * Erases the specified prefix from the trie.
       * The prefix is searched by non-recursively traversing the trie. If the
       * erase() finds the prefix, the counter of its occurences is decremented
       * and return value is set to TRUE.
       * If the erased prefix was the last one (i.e. prefix node has changed to
       * non-prefix node) and there is not more specific prefix (i.e. prefix
       * node is a leaf node of the trie), its corresponding node and all its
       * non-prefix predecessors (up to the closest node with two children) are
       * removed from the trie using private destruct().
       * If the erase() does not find the prefix, it silently ends without any
       * further action and with return value set to FALSE.
       * @param pref   Reference to the IP_prefix object representing the
       *               prefix that is to be removed.
       * @return       TRUE if the prefix was removed,
       *               FALSE otherwise.
       */
      bool erase(const IP_prefix& pref);

      /*
       * Prunes the trie in order to achieve the given characteristics.
       * The function first adjusts branching probability distributions at all
       * trie levels. Next, average skew and prefix length distributions are
       * adjusted while the number of prefixes in the trie is iteratively
       * decreased towards the given target size.
       * @param target_size    Target number of prefixes in the trie. The
       *                       final number of prefixes in the pruned trie can
       *                       be slightly different.
       * @param prefixes       The vector of target prefix length distribution
       *                       over the trie levels.
       * @param one_child      The vector of target one-child branching
       *                       probability distribution over the trie levels.
       * @param two_children   The vector of target two-children branching
       *                       probability distribution over the trie levels.
       * @param skew           The vector of target average skew distribution
       *                       over the trie levels.
       * @param iterations     The number of iterations of average skew and
       *                       prefix length distribution adjustment.
       */
      void prune(const int target_size,
                 const vector<float>& prefixes,
                 const vector<float>& one_child,
                 const vector<float>& two_children,
                 const vector<float>& skew,
                 const int iterations = 4);

      /*
       * Computes all defined trie statistics and stores them into a given
       * structure.
       * Except prefix nesting, which is computed during separate recursive
       * traversal, all the other statistics are computed during single
       * breadth-first search. Following statistics are actualized when
       * visiting the nodes:
       *    * classbench.prefix_lengths
       *    * classbench.skew
       *    * nodes.leaf
       *    * nodes.one_child
       *    * nodes.two_children
       *    * nodes.prefix
       *    * nodes.non_prefix
       * The value classbech.skew is also adjusted (divided by
       * nodes.two_children) after visiting all the nodes at the current trie
       * level.
       * There are also two statistics (classbench.branching_one_child and
       * classbench.branching_two_children) that are fully computed after
       * visiting all the nodes at the current trie level. Their computation is
       * based on values nodes.one_child and nodes.two_children.
       * @param stats   Reference to a data structure for computed trie
       *                statistics.
       */
      void get_stats(trie_stats& stats);
};

#endif
