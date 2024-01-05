// ip_prefix.h: header file for IP_prefix class
//
// Jiri Matousek, 2014
// imatousek@fit.vutbr.cz


#ifndef IP_PREFIX_H
#define IP_PREFIX_H


#include "uint128_t.h"
#include <string>

// Deafult namespace
using namespace std;


// ****************************************************************************
//                              Class declaration
// ****************************************************************************

/*
 * Class for representation of IPv4/IPv6 prefixes.
 *
 * IP prefixes are represented as bitstrings where the first character
 * represents the MSB of an IP address. Prefix length is determined by the
 * length of the bitstring.
 */
class IP_prefix {


   // ***** Private members ***************************************************


   private:
      /*
       * String of bits representing the prefix.
       * The first character represents the MSB of the prefix and the prefix
       * length is given by the length of this string.
       */
      string prefix;

      /*
       * Static function for conversion of a single byte into a bitstring.
       * @param byte   Byte to be converted.
       * @return       Byte converted into bitstring.
       */
      static string to_bitstring(unsigned short int byte);


   // ***** Public members ****************************************************


   public:
      /*
       * Default constructor.
       * Constructs an empty object of the IP_prefix class
       */
      inline IP_prefix() {};

      /*
       * Constructor.
       * Constructs an object of the IP_prefix class from a given string
       * representing either bits of an IPv4/IPv6 prefix (the length of the
       * string being the lenght of the prefix) or a valid IPv4/IPv6 prefix in
       * the standard notation.
       * @param str         String representing an IPv4/IPv6 prefix in a format
       *                    determined by the bitsring parameter.
       * @param bitstring   str represents bits of an IPv4/IPv6 prefix (TRUE)
       *                    or a valid IPv4/IPv6 prefix in the standard
       *                    notation (FALSE).
       */
      IP_prefix(const string& str, bool bitsring);

      /*
       * Constructor.
       * Constructs an object of the IP_prefix class from a given IPv4 prefix
       * represented by its address part (unsigned integer) and length
       * (integer).
       * @param addr   Address part of the IPv4 prefix.
       * @param len    Prefix length.
       */
      IP_prefix(unsigned addr, int len);

      /*
       * Constructor.
       * Constructs an object of the IP_prefix class from a given IPv4/IPv6
       * prefix represented by its address part (128-bit unsigned integer) and
       * length (integer).
       * @param addr   Address part of the IPv4/IPv6 prefix.
       * @param len    Prefix length.
       */
      IP_prefix(uint128_t addr, int len);

      /*
       * Copy assignment.
       * Constructs a new IP prefix object by asigning a copy of the original
       * IP prefix object.
       * @param orig   Reference to the original IP prefix object.
       * @return       Reference to the new IP prefix object.
       */
      IP_prefix& operator= (const IP_prefix& orig);

      /*
       * Comparison operator.
       * Compares the current IP prefix object with the given IP prefix object.
       * @param rhs_prefix   IP prefix object to be compared with the current
       *                     IP prefix object.
       * @return             TRUE if IP prefixes are equal,
       *                     FALSE otherwise.
       */
      inline bool operator== (const IP_prefix& rhs_prefix) const {
         return (prefix == rhs_prefix.get_prefix());
      }

      /*
       * Get function for the prefix bitstring.
       * @return   Bitstring representing IPv4/IPv6 prefix.
       */
      inline string get_prefix() const {
         return prefix;
      } // end get_prefix()

      /*
       * Get function for the prefix in the form of an unsigned integer.
       * @return   Unsigned integer representing IPv4 prefix.
       */
      unsigned get_prefix_unsigned() const;

      /*
       * Get function for the prefix in the form of a 128-bit unsigned
       * integer.
       * @return   128-bit unsigned integer representing IPv4/IPv6 prefix.
       */
      uint128_t get_prefix_uint128_t() const;

      /*
       * Get function for the prefix length.
       * @return   Prefix length.
       */
      inline int get_length() const {
         return prefix.length();
      } // end get_prefix()
};

#endif
