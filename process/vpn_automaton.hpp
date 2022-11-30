/**
 * \file vpn_automaton.hpp
 * \brief Plugin for parsing vpn_automaton traffic.
 * \author Jan Jirák jirakja7@fit.cvut.cz
 * \date 2022
 */
/*
 * Copyright (C) 2022 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPXP_PROCESS_VPN_AUTOMATON_HPP
#define IPXP_PROCESS_VPN_AUTOMATON_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define VPN_AUTOMATON_UNIREC_TEMPLATE "VPN_AUTOMATON_CONF_LEVEL"

UR_FIELDS (
   uint8 VPN_AUTOMATON_CONF_LEVEL
)

/**
 * \brief Flow record extension header for storing parsed VPN_AUTOMATON data.
 */
struct RecordExtVPN_AUTOMATON : public RecordExt {
   static int REGISTERED_ID;

   uint8_t possible_vpn;

   RecordExtVPN_AUTOMATON() : RecordExt(REGISTERED_ID)
   {
      possible_vpn = 0;
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_VPN_AUTOMATON_CONF_LEVEL, possible_vpn);
   }

   const char *get_unirec_tmplt() const
   {
      return VPN_AUTOMATON_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      if (size < 1) {
         return -1;
      }
      buffer[0] = (uint8_t) possible_vpn;
      return 1;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_VPN_AUTOMATON_TEMPLATE(IPFIX_FIELD_NAMES)
         NULL
      };
      return ipfix_template;
   }
};

/**
 * \brief Process plugin for parsing VPN_AUTOMATON packets.
 */
class VPN_AUTOMATONPlugin : public ProcessPlugin
{
public:
   VPN_AUTOMATONPlugin();
   ~VPN_AUTOMATONPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("vpn_automaton", "Parse VPN_AUTOMATON traffic"); }
   std::string get_name() const { return "vpn_automaton"; }
   RecordExt *get_ext() const { return new RecordExtVPN_AUTOMATON(); }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_VPN_AUTOMATON_HPP */

