// ip_prefix.cc: IP_prefix class definition
//
// Jiri Matousek, 2014
// imatousek@fit.vutbr.cz


// User includes
#include "ip_prefix.h"

// Library includes
#include <network>
#include <string>
#include <cstdlib>


// Namespace aliases
namespace ip = std::experimental::net::ip;

// Deafult namespace
using namespace std;


// ****************************************************************************
//                            Function definitions
// ****************************************************************************


// ***** Private functions ****************************************************


string IP_prefix::to_bitstring(unsigned short int byte) {
   string result = "00000000";
   for (int i = 7; i >= 0; i--) {
      if (byte > 0) {
         if (byte % 2 == 0) {
            result[i] = '0';
         } else {
            result[i] = '1';
         }
         byte /= 2;
      }
   }
   return result;
} // end to_bitstring()


// ***** Public functions *****************************************************


IP_prefix::IP_prefix(const string& str, bool bitstring) {
   if (bitstring) { // str represents bits of an IPv4/IPv6 prefix
      prefix = str;
   } else { // str represents a valid IPv4/IPv6 prefix in the standard notation
      // extract prefix
      string pref = str.substr(0, str.find('/'));
      // extract prefix length
      int len = atoi(str.substr(str.find('/')+1).c_str());

      // transform address part of the prefix into generic format
      ip::address addr(pref);

      // transform generic format into bitstring format
      string addr_bitstring;
      if (addr.is_v4()) { // IPv4
         ip::address_v4 addr_v4(pref);
         ip::address_v4::bytes_type addr_v4_bytes = addr_v4.to_bytes();
         for (ip::address_v4::bytes_type::iterator it = addr_v4_bytes.begin(); it != addr_v4_bytes.end(); ++it) {
            addr_bitstring.append(to_bitstring(*it));
         }
      } else if (addr.is_v6()){ // IPv6
         ip::address_v6 addr_v6(pref);
         ip::address_v6::bytes_type addr_v6_bytes = addr_v6.to_bytes();
         for (ip::address_v6::bytes_type::iterator it = addr_v6_bytes.begin(); it != addr_v6_bytes.end(); ++it) {
            addr_bitstring.append(to_bitstring(*it));
         }
      }

      // store only bits actually involved in IP prefix
      prefix = addr_bitstring.substr(0, len);
   }
} // end IP_prefix()


IP_prefix::IP_prefix(unsigned addr, int len) {
   // bitstring representation of addr
   string addr_bitstring;

   // convert addr into bitstring representation
   addr_bitstring.append(to_bitstring(addr >> 24));
   addr_bitstring.append(to_bitstring(addr >> 16));
   addr_bitstring.append(to_bitstring(addr >>  8));
   addr_bitstring.append(to_bitstring(addr));

   // store only bits actually involved in IP prefix
   prefix = addr_bitstring.substr(0, len);
} // end IP_prefix()


IP_prefix::IP_prefix(uint128_t addr, int len) {
   // bitstring representation of addr
   string addr_bitstring;

   // convert addr into bitstring representation
   addr_bitstring.append(to_bitstring(addr >> 120));
   addr_bitstring.append(to_bitstring(addr >> 112));
   addr_bitstring.append(to_bitstring(addr >> 104));
   addr_bitstring.append(to_bitstring(addr >> 96));
   addr_bitstring.append(to_bitstring(addr >> 88));
   addr_bitstring.append(to_bitstring(addr >> 80));
   addr_bitstring.append(to_bitstring(addr >> 72));
   addr_bitstring.append(to_bitstring(addr >> 64));
   addr_bitstring.append(to_bitstring(addr >> 56));
   addr_bitstring.append(to_bitstring(addr >> 48));
   addr_bitstring.append(to_bitstring(addr >> 40));
   addr_bitstring.append(to_bitstring(addr >> 32));
   addr_bitstring.append(to_bitstring(addr >> 24));
   addr_bitstring.append(to_bitstring(addr >> 16));
   addr_bitstring.append(to_bitstring(addr >>  8));
   addr_bitstring.append(to_bitstring(addr));

   // store only bits actually involved in IP prefix
   prefix = addr_bitstring.substr(0, len);
} // end IP_prefix()


IP_prefix& IP_prefix::operator= (const IP_prefix& orig) {
   // create a copy of class members
   prefix = orig.get_prefix();
   // return the created object
   return *this;
} // end operator= ()


unsigned IP_prefix::get_prefix_unsigned() const {
   // initialize auxiliary variables
   unsigned prefix_uns = 0;
   unsigned pow = 1;

   // iterate over all bits of an unsigned integer from right to left
   for (int i = 31; i >= 0; i--) {
      if (i < (int)prefix.length()) {
         if (prefix[i] == '1') {
            prefix_uns += pow;
         }
      }
      pow += pow;
   }

   // return the prefix value
   return prefix_uns;
} // end get_prefix_unsigned();


uint128_t IP_prefix::get_prefix_uint128_t() const {
   // initialize auxiliary variables
   uint128_t prefix_uns128 = 0;
   uint128_t pow = 1;

   // iterate over all bits of a 128-bit unsigned integer from right to left
   for (int i = 127; i >= 0; i--) {
      if (i < (int)prefix.length()) {
         if (prefix[i] == '1') {
            prefix_uns128 += pow;
         }
      }
      pow += pow;
   }

   // return the prefix value
   return prefix_uns128;
} // end get_prefix_uint128_t();
