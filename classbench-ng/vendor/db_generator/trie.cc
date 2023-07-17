// trie.cc: trie class definition
//
// Jiri Matousek, 2014
// imatousek@fit.vutbr.cz


// User includes
#include "trie.h"

// Library includes
#include <vector>
#include <queue>
#include <stack>
#include <string>
#include <cmath>
#include <climits>


// Default namespace
using namespace std;


// ****************************************************************************
//                        Auxiliary class definitions
// ****************************************************************************

class trie_nodes_greater_than_prefixes {
public:
    // implements operation "node1 is GREATER THAN node2"
    // according to the number of prefixes
    bool operator()(trie_node* node1, trie_node* node2)
    {
       if (node2->prefixes < node1->prefixes) {
          return true;
       } else {
          return false;
       }
    }
};

class trie_nodes_greater_than_weight {
public:
    // implements operation "node1 is GREATER THAN node2"
    // according to the total weight of nodes' subtrees
    bool operator()(trie_node* node1, trie_node* node2)
    {
       if ((node2->zero_weight + node2->one_weight) <
           (node1->zero_weight + node1->one_weight)) {
          return true;
       } else {
          return false;
       }
    }
};


// ****************************************************************************
//                            Function definitions
// ****************************************************************************


// ***** Private functions ****************************************************


trie_node* Trie::copy(const trie_node* node, int level) {
   // create a pointer to the root of a new trie
   trie_node* copy_root;
   // copy the given subtree
   if (node != NULL) { // non-empty subtree
      copy_root = new trie_node;
      copy_root->level = level;
      copy_root->prefixes = node->prefixes;
      copy_root->prefix_nesting_branches = node->prefix_nesting_branches;
      copy_root->zero = copy(node->zero, level+1);
      copy_root->zero_weight = node->zero_weight;
      copy_root->one  = copy(node->one, level+1);
      copy_root->one_weight = node->one_weight;
   } else { // empty subtree
      copy_root = NULL;
   }
   // return the pointer to the root node of the copy
   return copy_root;
} // end copy()


void Trie::destruct(trie_node* node) {
   if (node != NULL) { // non-empty subtree
      destruct(node->zero);
      destruct(node->one);
      delete node;
   }
   return;
} // end destruct()


int Trie::compute_weights(trie_node* node) {
   if (node != NULL) { // non-empty subtree
      node->zero_weight = compute_weights(node->zero);
      node->one_weight = compute_weights(node->one);
      return node->zero_weight + node->one_weight + node->prefixes;
   } else { // empty subtree
      return 0;
   }
} // end compute_weights()


float Trie::compute_skew(trie_node* node) {
   if (node->zero_weight > node->one_weight) { // lighter 1-subtree
      return 1 - ((float)node->one_weight / (float)node->zero_weight);
   } else { // lighter 0-subtree
      return 1 - ((float)node->zero_weight / (float)node->one_weight);
   }
} // end compute_skew()


int Trie::get_prefix_nesting(const trie_node* node) {
   if (node != NULL) { // non-empty subtree
      // get prefix nesting from successor nodes
      int zero_nesting = get_prefix_nesting(node->zero);
      int one_nesting = get_prefix_nesting(node->one);
      // will this node increase prefix nesting?
      int is_prefix;
      if (node->prefixes > 0) { // this is a prefix node
         is_prefix = 1;
      } else {
         is_prefix = 0;
      }
      // return maximum of successors' nesting, possibly incremented
      if (zero_nesting > one_nesting) {
         return zero_nesting + is_prefix;
      } else {
         return one_nesting + is_prefix;
      }
   } else { // empty subtree
      return 0;
   }
} // end get_prefix_nesting()


void Trie::remove_lightest_subtree(queue<trie_node*> q, bool one_child,
                                   int prefix_nesting_branches) {
   trie_node** lightest_subtree_ptr = NULL;
   int* lightest_weight_ptr = NULL;
   // find the lightest subtree of nodes stored in the queue
   while (!q.empty()) {
      // dequeue front element
      trie_node* node = q.front();
      q.pop();
      // auxiliary variables
      trie_node** subtree_ptr = NULL;
      int* weight_ptr = NULL;
      if (one_child) { // consider only nodes with one child
         // consider only nodes that can become a valid leaf node
         if (node->prefixes > 0) {
            // one-subtree only
            if ((node->zero == NULL) && (node->one != NULL)) {
               // the last maximum prefix nesting branch is not going through
               // the one-subtree
               if (node->one->prefix_nesting_branches <
                   prefix_nesting_branches) {
                  subtree_ptr = &(node->one);
                  weight_ptr = &(node->one_weight);
               }
            // zero-subtree only
            } else if ((node->zero != NULL) && (node->one == NULL)) {
               // the last maximum prefix nesting branch is not going through
               // the zero-subtree
               if (node->zero->prefix_nesting_branches <
                   prefix_nesting_branches) {
                  subtree_ptr = &(node->zero);
                  weight_ptr = &(node->zero_weight);
               }
            }
         }
      } else { // consider only nodes with two children
         if ((node->zero != NULL) && (node->one != NULL)) {
            // determine lighter subtree
            if (node->zero_weight <= node->one_weight) {
               // the last maximum prefix nesting branch is not going through
               // the zero-subtree
               if (node->zero->prefix_nesting_branches <
                   prefix_nesting_branches) {
                  subtree_ptr = &(node->zero);
                  weight_ptr = &(node->zero_weight);
               }
            } else {
               // the last maximum prefix nesting branch is not going through
               // the one-subtree
               if (node->one->prefix_nesting_branches <
                   prefix_nesting_branches) {
                  subtree_ptr = &(node->one);
                  weight_ptr = &(node->one_weight);
               }
            }
         }
      }
      // no lightest subtree has been found so far
      if (lightest_weight_ptr == NULL) {
         if (weight_ptr != NULL) { // new candidate for the lightest subtree
            lightest_subtree_ptr = subtree_ptr;
            lightest_weight_ptr = weight_ptr;
         }
      } else { // a candidate for the lightest subtree has already been found
         if (weight_ptr != NULL) { // new candidate for the lightest subtree
            // new lightest subtree
            if ((*weight_ptr) < (*lightest_weight_ptr)) {
               lightest_subtree_ptr = subtree_ptr;
               lightest_weight_ptr = weight_ptr;
            }
         }
      }
   } // end of while (!q.empty())
   // if lightest subtree, which can be removed, has been found
   if (lightest_subtree_ptr != NULL) {
      destruct(*lightest_subtree_ptr);
      *lightest_subtree_ptr = NULL;
      *lightest_weight_ptr = 0;
   }
   return;
} // end remove_lightest_subtree()


int Trie::mark_prefix_nesting_branches(trie_node* node, int prefix_nesting,
                                       int seen_prefixes) {
   if (node == NULL) { // empty subtree
      return 0;
   }
   if (node->prefixes > 0) { // the current root node is a prefix node
      seen_prefixes++;
   }
   // when a prefix nesting branch has been found
   if (seen_prefixes == prefix_nesting) {
      node->prefix_nesting_branches = 1;
   } else { // look for maximum prefix nesting branches in subtrees
      int branches_zero = mark_prefix_nesting_branches(node->zero,
                                                       prefix_nesting,
                                                       seen_prefixes);
      int branches_one = mark_prefix_nesting_branches(node->one,
                                                      prefix_nesting,
                                                      seen_prefixes);
      node->prefix_nesting_branches = branches_zero + branches_one;
   }
   return node->prefix_nesting_branches;
} // end mark_refix_nesting_branches()


int Trie::get_removable_prefixes(trie_node* node) {
   if (node == NULL) {
      return 0;
   }
   int removable_prefixes_zero = get_removable_prefixes(node->zero);
   int removable_prefixes_one  = get_removable_prefixes(node->one);
   int removable_prefixes_this = node->prefixes;
   // keep at least one prefix in a leaf node
   if ((node->zero == NULL) && (node->one == NULL)) {
      removable_prefixes_this--;
   }
   // different handling for 2-children node
   if ((node->zero != NULL) && (node->one != NULL)) {
      // allow removing prefixes from subtrees only if both subtrees contain
      // removable prefixes
      if ((removable_prefixes_zero > 0) && (removable_prefixes_one > 0)) {
         // initialize auxiliar variables
         int zero_weight = node->zero_weight;
         int one_weight = node->one_weight;
         int d = 1; // divisor of zero_weight and one_weight
         int x = 0; // to be removed prefixes from zero subtree
         int y = 0; // to be removed prefixes from one subtree
         // find x and y such that
         //    a) x <= removable_prefixes_zero
         //    b) y <= removable_prefixes_one
         // where
         //    x = zero_weight - (zero_weight / gcd)
         //    y = one_weight - (one_weight / gcd)
         // and gcd is the gratest common divisor of zero_weight and one_weight
         while ((d <= zero_weight) && (d <= one_weight)) {
            // if d is the gcd
            if (((zero_weight % d) == 0) && ((one_weight % d) == 0)) {
               // if to be removed prefixes from both zero and one subtrees is
               // smaller than removable prefixes from these subtrees
               if ((zero_weight - zero_weight / d <= removable_prefixes_zero)
                   &&
                   (one_weight - one_weight / d <= removable_prefixes_one)) {
                  x = zero_weight - (zero_weight / d);
                  y = one_weight - (one_weight / d);
               } else {
                  break;
               }
            }
            d++;
         }
         // return the total number of prefixes that can be removed without
         // altering the skew
         return removable_prefixes_this +
                x +
                y;
      } else {
         return removable_prefixes_this;
      }
   } else {
      return removable_prefixes_this +
             removable_prefixes_zero +
             removable_prefixes_one;
   }
} // end get_removable_prefixes


void Trie::adjust_node_skew(trie_node* node, float target_skew) {
   // initialize lighter_* and heavier_* variables
   int lighter_weight;
   int heavier_weight;
   trie_node* lighter_subtree;
   trie_node* heavier_subtree;
   // initialize auxiliary variables for skew computation
   float skew;
   int zero_weight = node->zero_weight;
   int one_weight = node->one_weight;
   // compute skew of the given node and set lighter_* and heavier_* variables
   if (zero_weight > one_weight) { // zero subtree is heavier
      skew = 1 - ((float)one_weight / (float)zero_weight);
      lighter_weight = one_weight;
      heavier_weight = zero_weight;
      lighter_subtree = node->one;
      heavier_subtree = node->zero;
   } else { // one subtree is heavier
      skew = 1 - ((float)zero_weight / (float)one_weight);
      lighter_weight = zero_weight;
      heavier_weight = one_weight;
      lighter_subtree = node->zero;
      heavier_subtree = node->one;
   }
   // initialize auxiliary variables
   double new_weight_real;
   int weight;
   trie_node* subtree;
   // decrease working skew - remove prefixes from heavier subtree
   if ((skew - target_skew) > 0) {
      new_weight_real = lighter_weight / (1 - target_skew);
      weight = heavier_weight;
      subtree = heavier_subtree;
   // increase working skew - remove prefixes from lighter subtree
   } else {
      new_weight_real = heavier_weight * (1 - target_skew);
      weight = lighter_weight;
      subtree = lighter_subtree;
   }
   // determine new integer weight of a selected subtree
   int new_weight = round(new_weight_real);
   // determine number of prefixes that will be removed
   int remove_prefixes = weight - new_weight;
   int removable_prefixes = get_removable_prefixes(subtree);
   if (remove_prefixes > removable_prefixes) {
      // decrease the number of removed prefixes to the maximum number of
      // prefixes that can be removed
      remove_prefixes = removable_prefixes;
   }
   // make the selected subtree lighter by removing the given number of
   //prefixes
   make_subtree_lighter(subtree, remove_prefixes);
   compute_weights(node);
   return;
} // end adjust_node_skew()


void Trie::make_subtree_lighter(trie_node* root, int remove_prefixes) {
   // nothing to do when the subtree is empty or 0 prefixes are to be removed
   if ((root == NULL) || (remove_prefixes == 0)) {
      return;
   }
   // auxiliary variables for counting statistics
   trie_node* node = root;
   int removable_prefixes_node = 0;
   int removable_prefixes_branch = 0;
   // in priority queue, nodes with less prefixes have higher priority
   priority_queue<trie_node*,
                  vector<trie_node*>,
                  trie_nodes_greater_than_prefixes> pq;
   // initialize auxiliary variables (keep at least one prefix in a leaf node)
   removable_prefixes_node = node->prefixes;
   if ((node->zero == NULL) && (node->one == NULL)) {
      removable_prefixes_node--;
   }
   if (removable_prefixes_node > 0) {
      removable_prefixes_branch = removable_prefixes_node;
      pq.push(node);
   }
   // traverse a non-branching part of the subtree (i.e. up to the closest
   // 2-children node or a leaf node) and compute basic statistics about it
   while (((node->zero == NULL) && (node->one != NULL)) ||
          ((node->zero != NULL) && (node->one == NULL))) {
      // determine the next step
      if (node->zero == NULL) {
         node = node->one;
      } else {
         node = node->zero;
      }
      // compute statistics (keep at least one prefix in a leaf node)
      removable_prefixes_node = node->prefixes;
      if ((node->zero == NULL) && (node->one == NULL)) {
         removable_prefixes_node--;
      }
      if (removable_prefixes_node > 0) {
         removable_prefixes_branch += removable_prefixes_node;
         pq.push(node);
      }
   }
   // get the number of removable prefixes in the remaining subtree
   int removable_prefixes_subtree = get_removable_prefixes(node);
   int removable_prefixes_zero = 0;
   // adjust it to not contain removable prefixes of the subtree's root node
   if ((node->zero == NULL) && (node->one == NULL)) {
      removable_prefixes_subtree = 0;
   } else {
      removable_prefixes_subtree -= node->prefixes;
   }
   // get the number of removable prefixes in branches of the remaining subtree
   if (removable_prefixes_subtree > 0) {
      int subtree_weight = node->zero_weight + node->one_weight;
      removable_prefixes_zero =
         round(((float)node->zero_weight / (float)subtree_weight) *
               removable_prefixes_subtree);
   }
   // do not continue when no removable prefixes in the branch nor the subtree
   if ((removable_prefixes_branch + removable_prefixes_subtree) == 0) {
      return;
   }
   // distribute prefixes that are to be removed between the branch and the
   // subtree
   int remove_prefixes_branch = round(((float)removable_prefixes_branch /
                                       (float)(removable_prefixes_subtree +
                                               removable_prefixes_branch)) *
                                      remove_prefixes);
   int remove_prefixes_subtree = remove_prefixes - remove_prefixes_branch;
   // initialize auxiliary variable for test purposes
   int removed_prefixes_branch = 0;
   // while there are some prefix nodes in the branch, remove prefixes
   // proportionally from all these nodes
   while (!pq.empty()) {
      // deque the front element from the priority queue
      trie_node* working_node = pq.top();
      pq.pop();
      // determine the number of prefixes that are to be removed from this node
      int remove_prefixes_node;
      if (!pq.empty()) { // not the last node of the branch
         // keep at least one prefix in a leaf node
         removable_prefixes_node = working_node->prefixes;
         if ((node->zero == NULL) && (node->one == NULL)) {
            removable_prefixes_node--;
         }
         // the nuber of prefixes to be removed is computed proportionally
         remove_prefixes_node = round(((float)removable_prefixes_node /
                                       (float)removable_prefixes_branch) *
                                      remove_prefixes_branch);
      } else { // the last node of the branch
         // the number of prefixes to be removed ensures removing all the remaining prefixes
         remove_prefixes_node = remove_prefixes_branch - removed_prefixes_branch;
      }
      // remove the given number of prefixes
      working_node->prefixes -= remove_prefixes_node;
      // adjust the test variable
      removed_prefixes_branch += remove_prefixes_node;
   }
   // the last node in the non-branching part of the subtree is a 2-children
   // node
   if ((node->zero != NULL) && (node->one != NULL)) {
      // there are some prefixes to be removed from the subtree rooted at node
      if (remove_prefixes_subtree > 0) {
         // distribute prefixes that are to be removed from from the subtree
         // between its zero and one subtrees
         int remove_prefixes_zero = round(((float)removable_prefixes_zero /
                                           (float)removable_prefixes_subtree) *
                                          remove_prefixes_subtree);
         int remove_prefixes_one  = remove_prefixes_subtree -
                                    remove_prefixes_zero;
         // remove prefixes from subtrees of the 2-children node
         compute_weights(node);
         make_subtree_lighter(node->zero, remove_prefixes_zero);
         make_subtree_lighter(node->one, remove_prefixes_one);
         compute_weights(node);
      }
   }
   return;
} // end make_subtree_lighter()


trie_node* Trie::remove_nonprefix_branches(trie_node* node) {
   if (node != NULL) { // non-empty subtree
      node->zero = remove_nonprefix_branches(node->zero);
      node->one = remove_nonprefix_branches(node->one);
      if ((node->zero == NULL) && (node->one == NULL) &&
          (node->prefixes == 0)) {
         delete node;
         return NULL;
      }
   }
   return node;
} //end remove_nonprefix_branches()


void Trie::adjust_branching(vector<float> branching_one_child,
                            vector<float> branching_two_children) {
   // nothing to do when the trie is empty
   if (root == NULL) {
      return;
   }
   // recursively compute weight of all subtrees
   compute_weights(root);
   // recursively compute maximum prefix nesting
   int prefix_nesting = get_prefix_nesting(root);
   // mark branches with maximum prefix nesting
   mark_prefix_nesting_branches(root, prefix_nesting, 0);
   // initialize auxiliary variables
   queue<trie_node*> q;
   q.push(root);
   int level = -1;
   // do a breadth-first search
   while (!q.empty()) {
      // get pointer to the front element
      trie_node* node = q.front();
      // first node at this level - perform branching adjustment
      // (all nodes from the current level are enqueued)
      if (node->level != level) {
         level = node->level;
         // compute branching statistics for this level
         queue<trie_node*> q_copy (q);
         int one_child = 0;
         int two_children = 0;
         int sum = 0;
         while (!q_copy.empty()) {
            // dequeue front element from the auxiliary queue
            trie_node* node_copy = q_copy.front();
            q_copy.pop();
            // increment correct counter
            if ((node_copy->zero != NULL) && (node_copy->one != NULL)) {
               two_children++;
            } else if ((node_copy->zero != NULL) || (node_copy->one != NULL)) {
               one_child++;
            }
         }
         sum = one_child + two_children;
         // branching probabilities are defined at this level
         if (sum != 0) { // there is some branching at this level
            float current_branching_two = (float) two_children / (float) (sum);
            // adjust branching by reducing the number of two-children nodes
            if (current_branching_two > branching_two_children[level]) {
               // determine the ideal number of subtree removing steps
               float remove_subtrees = two_children -
                                       (branching_two_children[level] * sum);
               // diff from ideal branching when remove min./max. subtrees
               float diff_min = ((two_children - floor(remove_subtrees)) / sum)
                                - branching_two_children[level];
               float diff_max = branching_two_children[level] -
                                ((two_children - ceil(remove_subtrees)) / sum);
               // determine the number of subtree removing steps
               int remove_steps = 0;
               if (diff_min <= diff_max) {
                  remove_steps = (int) floor(remove_subtrees);
               } else {
                  remove_steps = (int) ceil(remove_subtrees);
               }
               // remove the given number of "lightest" subtrees +
               // actualize markers of maximum prefix nesting branches
               for (int i = 0; i < remove_steps; i++) {
                  remove_lightest_subtree(q, false,
                                          root->prefix_nesting_branches);
                  mark_prefix_nesting_branches(root, prefix_nesting, 0);
               }
               // adjust branching nodes count variables
               one_child += remove_steps;
               two_children -= remove_steps;
            }
            // removing subtree of one-child nodes can change branching
            // probabilities
            if (two_children != 0) {
               float current_branching_one = (float) one_child / (float) (sum);
               // adjust branching by reducing the number of one-child nodes
               if (current_branching_one > branching_one_child[level]) {
                  // determine the ideal number of subtree removing steps
                  float remove_subtrees =
                     ((branching_one_child[level] * sum) - one_child) /
                     (branching_one_child[level] - 1);
                  // diff from ideal branching when remove min./max. subtrees
                  float diff_min = ((one_child - floor(remove_subtrees)) /
                                    (sum - floor(remove_subtrees))) -
                                   branching_one_child[level];
                  float diff_max = branching_one_child[level] -
                                   ((one_child - ceil(remove_subtrees)) /
                                    (sum - ceil(remove_subtrees)));
                  // determine the number of subtree removing steps
                  int remove_steps = 0;
                  if (diff_min <= diff_max) {
                     remove_steps = (int) floor(remove_subtrees);
                  } else {
                     remove_steps = (int) ceil(remove_subtrees);
                  }
                  // remove the given number of "lightest" subtrees +
                  // actualize markers of maximum prefix nesting branches
                  for (int i = 0; i < remove_steps; i++) {
                     remove_lightest_subtree(q, true,
                                             root->prefix_nesting_branches);
                     mark_prefix_nesting_branches(root, prefix_nesting, 0);
                  }
                  one_child -= remove_steps;
                  sum -= remove_steps;
               }
            }
         } // end of if (sum != 0)
      } // end of if (node->level != level)
      // enqueue possible successors of the current node
      if (node->zero != NULL) {
         q.push(node->zero);
      }
      if (node->one != NULL) {
         q.push(node->one);
      }
      // remove the front element from the queue
      q.pop();
   } // end of while (!q.empty())
   return;
} // end adjust_branching()


void Trie::adjust_skew(vector<float> skew, float skew_epsilon) {
   // nothing to do when the trie is empty
   if (root == NULL) {
      return;
   }
   // initialize auxiliary variables
   queue<trie_node*> q;
   stack<trie_node*> s;
   q.push(root);
   // do a breadth-first search
   while (!q.empty()) {
      // dequeue front element from the queue
      trie_node* node = q.front();
      q.pop();
      // store nodes with 2 children into a stack
      if ((node->zero != NULL) && (node->one != NULL)) {
         s.push(node);
      }
      // enqueue possible successors of the current node
      if (node->zero != NULL) {
         q.push(node->zero);
      }
      if (node->one != NULL) {
         q.push(node->one);
      }
   }
   // initialize auxiliary variables
   // in priority queue, lighter nodes have higher priority
   priority_queue<trie_node*,
                  vector<trie_node*>,
                  trie_nodes_greater_than_weight> pq;
   float total_skew = 0.0;
   int level;
   if (!s.empty()) {
      level = s.top()->level;
   }
   // do inverse breadth-first search on two-children nodes
   while (!s.empty()) {
      // pop top element from the stack
      trie_node* node = s.top();
      s.pop();
      // next level - adjust total skew of the current level
      if (level != node->level)  {
         // store the number of 2-children nodes at current level
         int two_children_nodes = pq.size();
         // compute target total skew ("sum of all skew values at this level")
         float target_total_skew = skew[level] * two_children_nodes;
         // compute skew that is going to be added/removed
         float skew_change = target_total_skew - total_skew;
         // compute average skew that is going to be added/removed
         float average_skew_change;
         if (two_children_nodes > 0) {
            average_skew_change = skew_change / (float)two_children_nodes;
         } else {
            average_skew_change = skew_change;
         }
         // iteratively adjust total skew at this level
         while (!pq.empty()) {
            // skip further skew adjustment when average_skew_change is less
            // than the given skew_epsilon
            if (abs(average_skew_change) < skew_epsilon) {
               // remove remaining nodes from the priority queue
               while (!pq.empty()) {
                  pq.pop();
               }
               // end the outer "while (!pq.empty())" loop
               break;
            }
            // pop the top element from the priority queue
            trie_node* working_node = pq.top();
            pq.pop();
            // compute original skew of the working node
            float original_skew = compute_skew(working_node);
            float target_skew = original_skew + skew_change;
            // adjust skew of the working node
            if (target_skew < 0.0) {
               target_skew = 0.0;
            } else if (target_skew > 1.0) {
               target_skew = 1.0;
            }
            adjust_node_skew(working_node, target_skew);
            // recursively compute weight of node's subtrees
            compute_weights(working_node);
            // compute adjusted skew of the working node
            float adjusted_skew = compute_skew(working_node);
            // update total skew, skew that is going to be added/removed, and
            // its average value
            total_skew = total_skew - original_skew + adjusted_skew;
            skew_change = target_total_skew - total_skew;
            two_children_nodes = pq.size();
            if (two_children_nodes > 0) {
               average_skew_change = skew_change / (float)two_children_nodes;
            } else {
               average_skew_change = skew_change;
            }
         }
         level = node->level;
         total_skew = 0.0;
      }
      // recursively compute weight of node's subtrees
      compute_weights(node);
      // insert the node into the priority queue
      pq.push(node);
      // actualize total skew value
      total_skew += compute_skew(node);
   }
   return;
} // end adjust_skew()


void Trie::adjust_prefixes(vector<float> prefixes_proportion,
                           const int target_size) {
   // nothing to do when the trie is empty
   if (root == NULL) {
      return;
   }
   // compute the total number of prefixes at each level
   vector<int> all_prefixes(129,0);
   queue<trie_node*> q;
   q.push(root);
   while (!q.empty()) {
      // dequeue front element
      trie_node* node = q.front();
      q.pop();
      // enqueue its possible successors
      if (node->zero != NULL) {
         q.push(node->zero);
      }
      if (node->one != NULL) {
         q.push(node->one);
      }
      // update the total number of prefixes at current level
      all_prefixes[node->level] += node->prefixes;
   }
   // compute the number of target and to be removed prefixes at each level
   vector<int> target_prefixes(129,0);
   vector<int> remove_prefixes(129,0);
   int target_prefixes_total = 0;
   int leaf_level = 0;
   for (int i = 0; i < (int) prefixes_proportion.size(); i++) {
      target_prefixes[i] = round(prefixes_proportion[i]*target_size);
      target_prefixes_total += target_prefixes[i];
      remove_prefixes[i] = all_prefixes[i] - target_prefixes[i];
      if (target_prefixes[i] != 0) {
         leaf_level = i;
      }
   }
   // final correction to given target_size
   if (target_prefixes_total != target_size) {
      int diff = target_size - target_prefixes_total;
      target_prefixes[leaf_level] += diff;
      target_prefixes_total += diff;
      remove_prefixes[leaf_level] -= diff;
   }
   // compute the number of prefixes to be removed at remaining levels
   vector<int> remove_prefixes_remaining(129,0);
   for (int i = 127; i >= 0; i--) {
      remove_prefixes_remaining[i] = remove_prefixes_remaining[i+1] +
                                     remove_prefixes[i+1];
   }
   // starting from the root, adjust prefixes distribution
   queue<trie_node*> nodes;
   nodes.push(root);
   queue<int> remove_prefixes_subtrees;
   remove_prefixes_subtrees.push(remove_prefixes[0] + remove_prefixes_remaining[0]);
   int level = -1;
   while (!nodes.empty()) {
      // get the front element
      // (from both nodes and remove_prefixes_subtrees queues)
      trie_node* node = nodes.front();
      // next level - adjust prefixes at this level
      // (all nodes of this level are stored in nodes queue)
      if (node->level != level) {
         level = node->level;
         // actualize subtrees' weight information in nodes
         compute_weights(root);
         // initialize vectors to contain all current elements of queues
         queue<trie_node*> nodes_copy (nodes);
         vector<trie_node*> nodes_vect;
         queue<int> remove_prefixes_subtrees_copy (remove_prefixes_subtrees);
         vector<int> remove_prefixes_subtrees_vect;
         while (!nodes_copy.empty()) {
            nodes_vect.push_back(nodes_copy.front());
            nodes_copy.pop();
            remove_prefixes_subtrees_vect.push_back(remove_prefixes_subtrees_copy.front());
            remove_prefixes_subtrees_copy.pop();
         }
         // from all leaf nodes at this level
         // remove prefixes that have to be removed
         int i = 0;
         while (i < (int) nodes_vect.size()) {
            if ((nodes_vect[i]->zero == NULL) &&
                (nodes_vect[i]->one == NULL)) {
               // determine the real number of prefixes to be removed
               // (do not remove the last prefix from a leaf node)
               int remove_prefixes_node;
               if (nodes_vect[i]->prefixes > remove_prefixes_subtrees_vect[i]) {
                  remove_prefixes_node = remove_prefixes_subtrees_vect[i];
               } else {
                  remove_prefixes_node = nodes_vect[i]->prefixes - 1;
               }
               // consider all prefixes of this node and this subtree to be
               // removed, regardless they are really removed or not
               // (in any case, there are no other prefixes that could be
               //  removed)
               all_prefixes[level] -= nodes_vect[i]->prefixes;
               remove_prefixes_subtrees_vect[i] = 0;
               // remove the prefixes
               nodes_vect[i]->prefixes -= remove_prefixes_node;
               remove_prefixes[level] -= remove_prefixes_node;
               // remove this node from both vectors
               nodes_vect.erase(nodes_vect.begin()+i);
               remove_prefixes_subtrees_vect.erase(remove_prefixes_subtrees_vect.begin()+i);
            } else {
               // the node has not been removed, thus increase the index
               i++;
            }
         }
         // if there are some nodes with prefixes that could be removed AND
         // the number of prefixes to be removed is not negative
         if ((all_prefixes[level] > 0) && (remove_prefixes[level] >= 0)) {
            // initialize auxiliary constant (for this level)
            float remove_all_ratio = (float)(remove_prefixes[level]) /
                                     (float)(all_prefixes[level]);
            // from all non-leaf nodes at this level
            // remove prefixes that are to be removed at this level
            for (int i = 0; i < (int) nodes_vect.size(); i++) {
               int remove_prefixes_node = round((float)(nodes_vect[i]->prefixes) *
                                                remove_all_ratio);
               // do not remove more than all prefixes to be removed from this subtree
               if (remove_prefixes_node > remove_prefixes_subtrees_vect[i]) {
                  remove_prefixes_node = remove_prefixes_subtrees_vect[i];
               }
               // do not remove more than all prefixes of this node
               if (remove_prefixes_node > nodes_vect[i]->prefixes) {
                  remove_prefixes_node = nodes_vect[i]->prefixes;
               }
               // remove the prefixes and adjust other variables
               nodes_vect[i]->prefixes -= remove_prefixes_node;
               all_prefixes[level] -= remove_prefixes_node;
               remove_prefixes[level] -= remove_prefixes_node;
               remove_prefixes_subtrees_vect[i] -= remove_prefixes_node;
            }
         }
         // for all nodes at this level
         // distribute prefixes to be removed in a subtree rooted at this node
         // into node's subtrees
         for (int i = 0; i < (int) nodes_vect.size(); i++) {
            // distribution for 2-children nodes
            if ((nodes_vect[i]->zero != NULL) && (nodes_vect[i]->one != NULL)) {
               // determine the distribution
               int total_weight = nodes_vect[i]->zero_weight +
                                  nodes_vect[i]->one_weight;
               int remove_prefixes_zero = round(((float)(nodes_vect[i]->zero_weight) /
                                                 (float)total_weight) *
                                                (float)(remove_prefixes_subtrees_vect[i]));
               int remove_prefixes_one = remove_prefixes_subtrees_vect[i] -
                                         remove_prefixes_zero;
               // do not remove more than all prefixes from zero subtree
               if (remove_prefixes_zero > nodes_vect[i]->zero_weight) {
                  remove_prefixes_zero = nodes_vect[i]->zero_weight;
               }
               // do not remove more than all prefixes from one subtree
               if (remove_prefixes_one > nodes_vect[i]->one_weight) {
                  remove_prefixes_one = nodes_vect[i]->one_weight;
               }
               // store the distribution into main queues
               nodes.push(nodes_vect[i]->zero);
               remove_prefixes_subtrees.push(remove_prefixes_zero);
               nodes.push(nodes_vect[i]->one);
               remove_prefixes_subtrees.push(remove_prefixes_one);
            } else {
               // distribution for 1-child nodes
               if (nodes_vect[i]->zero != NULL) {
                  nodes.push(nodes_vect[i]->zero);
               } else if (nodes_vect[i]->one != NULL) {
                  nodes.push(nodes_vect[i]->one);
               }
               remove_prefixes_subtrees.push(remove_prefixes_subtrees_vect[i]);
            }
         }
      }
      // remove the front elements from the main queues
      nodes.pop();
      remove_prefixes_subtrees.pop();
   }
   return;
} // end adjust_prefixes()


// ***** Public functions *****************************************************


// Default constructor
Trie::Trie() {
   root = NULL;
} // end Trie()


// Copy constructor
Trie::Trie(const Trie& orig) {
   root = copy(orig.get_root(), 0);
} // end Trie()


// Destructor
Trie::~Trie() {
   destruct(root);
} // end ~Trie()


// Copy assignment
Trie& Trie::operator= (const Trie& orig) {
   // replace the original trie by a copy of the assigned trie
   destruct(root);
   root = copy(orig.get_root(), 0);
   // return created object
   return *this;
} // end operator= ()


void Trie::insert(const IP_prefix& pref) {
   // insert at least a root node when the trie is empty
   if (root == NULL) {
      root = new trie_node;
      root->level = 0;
      root->prefixes = 0;
      root->prefix_nesting_branches = 0;
      root->zero = NULL;
      root->zero_weight = 0;
      root->one  = NULL;
      root->one_weight = 0;
   }
   // insert the given prefix into the trie
   if (pref.get_length() == 0) { // prefix of length 0
      (root->prefixes)++;
   } else { // prefix of length > 0
      // auxiliary variables
      trie_node* node = root;
      trie_node** next_node_ptr;
      string prefix = pref.get_prefix();
      // trie traversal
      for (int i = 0; i < pref.get_length(); i++) {
         // determine the next node and store the pointer to it
         if (prefix[i] == '0') {
            next_node_ptr = &(node->zero);
         } else { // (prefix[i] == '1')
            next_node_ptr = &(node->one);
         }
         // insert the next node if it does not exist
         if ((*next_node_ptr) == NULL) {
            (*next_node_ptr) = new trie_node;
            (*next_node_ptr)->level = i+1;
            (*next_node_ptr)->prefixes = 0;
            (*next_node_ptr)->prefix_nesting_branches = 0;
            (*next_node_ptr)->zero = NULL;
            (*next_node_ptr)->zero_weight = 0;
            (*next_node_ptr)->one  = NULL;
            (*next_node_ptr)->one_weight  = 0;
         }
         // move to the next node;
         node = (*next_node_ptr);
      }
      // prefix insertion
      (node->prefixes)++;
   }
   return;
} // end insert()


bool Trie::erase(const IP_prefix& pref) {
   // nothing to do when the trie is empty
   if (root == NULL) {
      return root;
   }
   // search for the given prefix
   if (pref.get_length() == 0) { // prefix of length 0
      if (root->prefixes > 0) { // we have found the prefix node
         (root->prefixes)--;
         if ((root->prefixes == 0) &&
             (root->zero == NULL) &&
             (root->one  == NULL)) {
            // all the conditions for removing the node were met
            destruct(root);
            root = NULL;
         }
         return true;
      } else { // the corresponding node is a non-prefix node
         return false;
      }
   } else { // prefix of length > 0
      // auxiliary variables
      trie_node* node = root;
      trie_node** destruct_root = &(root);
      string prefix = pref.get_prefix();
      for (int i = 0; i < pref.get_length(); i++) {
         // determine the next node
         if (prefix[i] == '0') {
            // adjust desctruct_root
            if ((node->prefixes != 0) ||
                (node->one != NULL)) { // this node cannot be removed
               destruct_root = &(node->zero);
            }
            // move to the next node
            node = node->zero;
         } else { // (prefix[i] == '1')
            // adjust desctruct_root
            if ((node->prefixes != 0) ||
                (node->zero != NULL)) { // this node cannot be removed
               destruct_root = &(node->one);
            }
            // move to the next node
            node = node->one;
         }
         // chceck whether the next node exists (terminate search if not)
         if (node == NULL) {
            return false;
         }
      }
      if (node->prefixes > 0) { // we have found the prefix node
         (node->prefixes)--;
         if ((node->prefixes == 0) &&
             (node->zero == NULL) &&
             (node->one  == NULL)) {
            // all the conditions for removing the node were met
            destruct(*destruct_root);
            *destruct_root = NULL;
         }
         return true;
      } else { // the corresponding node is a non-prefix node
         return false;
      }
   }
} // end erase()


void Trie::prune(const int target_size,
                 const vector<float>& prefixes,
                 const vector<float>& one_child,
                 const vector<float>& two_children,
                 const vector<float>& skew,
                 const int iterations) {
   // get original prefix set size
   trie_stats s;
   this->get_stats(s);
   int orig_size = s.classbench.prefixes;

   // adjust branching (1st step of trie pruning)
   this->adjust_branching(one_child, two_children);

   // iteratively adjust skew and prefixes proportion
   // (multiple iterations help to reduce the negative effect of
   //  adjust_prefixes function on skew)
   for (int i = 1; i <= iterations; i++) {
      // adjust skew (2nd step of trie pruning)
      this->adjust_skew(skew);
      // adjust prefixes proportion (3rd step of trie pruning)
      if (i == iterations) {
         this->adjust_prefixes(prefixes, target_size);
      } else {
         this->adjust_prefixes(prefixes, round((1-(float)i/4)*orig_size));
      }
   }
} // end prune()


void Trie::get_stats(trie_stats& stats) {
   // initialize classbench statistics
   stats.classbench.prefixes = 0;
   stats.classbench.prefix_lengths = vector<int>(129,0);
   stats.classbench.branching_one_child = vector<float>(129,0.0);
   stats.classbench.branching_two_children = vector<float>(129,0.0);
   stats.classbench.skew = vector<float>(129,0.0);
   stats.classbench.prefix_nesting = 0;
   // initialize nodes statistics
   stats.nodes.leaf = vector<int>(129,0);
   stats.nodes.one_child = vector<int>(129,0);
   stats.nodes.two_children = vector<int>(129,0);
   stats.nodes.prefix = vector<int>(129,0);
   stats.nodes.non_prefix = vector<int>(129,0);
   // nothing to do when the trie is empty
   if (root == NULL) {
      return;
   }
   // compute zero_weight and one_weight in each node of the trie
   compute_weights(root);
   // initialize auxiliary variables
   queue<trie_node*> q;
   q.push(root);
   int level = root->level;
   // do a breadth-first search
   while (!q.empty()) {
      // dequeue front element
      trie_node* node = q.front();
      q.pop();
      // enqueue its possible successors
      if (node->zero != NULL) {
         q.push(node->zero);
      }
      if (node->one != NULL) {
         q.push(node->one);
      }
      // level change - finish statistics computation for the previous level
      if (node->level != level) {
         // auxiliary variables
         int one_child = stats.nodes.one_child[level];
         int two_children = stats.nodes.two_children[level];
         int sum = one_child + two_children;
         // branching_one_child and branching_two_children
         if (sum != 0) {
            stats.classbench.branching_one_child[level] =
               (float)one_child / (float)sum;
            stats.classbench.branching_two_children[level] =
               (float)two_children / (float)sum;
         }
         // skew
         if (two_children != 0) {
            stats.classbench.skew[level] /= (float)two_children;
         }
         // increment the level counter
         level++;
      }
      // trie node visit - classbench statistics
      stats.classbench.prefixes += node->prefixes;
      stats.classbench.prefix_lengths[level] += node->prefixes;
      if ((node->zero != NULL) && (node->one != NULL)) { // skew is defined
         stats.classbench.skew[level] += compute_skew(node);
      }
      // trie node visit - nodes statistics
      if (node->zero == NULL) {
         if (node->one == NULL) { // leaf node
            (stats.nodes.leaf[level])++;
         } else { // one child node
            (stats.nodes.one_child[level])++;
         }
      } else { // node->zero != NULL
         if (node->one != NULL) { // two child node
            (stats.nodes.two_children[level])++;
         } else { // one child node
            (stats.nodes.one_child[level])++;
         }
      }
      if (node->prefixes > 0) { // prefix node
         (stats.nodes.prefix[level])++;
      } else { // non-prefix node
         (stats.nodes.non_prefix[level])++;
      }
   } // end of while (!q.empty())
   // finish statistics computation for the last level
   // auxiliary variables
   int one_child = stats.nodes.one_child[level];
   int two_children = stats.nodes.two_children[level];
   int sum = one_child + two_children;
   // branching_one_child and branching_two_children
   if (sum != 0) {
      stats.classbench.branching_one_child[level] =
         (float)one_child / (float)sum;
      stats.classbench.branching_two_children[level] =
         (float)two_children / (float)sum;
   }
   // skew
   if (two_children != 0) {
      stats.classbench.skew[level] /= (float)two_children;
   }
   // compute prefix nesting
   stats.classbench.prefix_nesting = get_prefix_nesting(root);
   return;
} // end get_stats()
