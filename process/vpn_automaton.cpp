/**
 * \file vpn_automaton.cpp
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

#include <iostream>

#include "vpn_automaton.hpp"

namespace ipxp {

int RecordExtVPN_AUTOMATON::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("vpn_automaton", [](){return new VPN_AUTOMATONPlugin();});
   register_plugin(&rec);
   RecordExtVPN_AUTOMATON::REGISTERED_ID = register_extension();
}

VPN_AUTOMATONPlugin::VPN_AUTOMATONPlugin()
{
}

VPN_AUTOMATONPlugin::~VPN_AUTOMATONPlugin()
{
   close();
}

void VPN_AUTOMATONPlugin::init(const char *params)
{
}

void VPN_AUTOMATONPlugin::close()
{
}

ProcessPlugin *VPN_AUTOMATONPlugin::copy()
{
   return new VPN_AUTOMATONPlugin(*this);
}

inline void transition_from_init(RecordExtVPN_AUTOMATON *automaton_data, uint16_t len, const timeval& ts, uint8_t dir)
{
   automaton_data->syn_table.update_entry(len, dir, ts);
}

inline void transition_from_syn(RecordExtVPN_AUTOMATON *automaton_data, uint16_t len, const timeval& ts, uint8_t dir)
{
   bool can_transit = automaton_data->syn_table.check_range_for_presence(len, 10, !dir, ts);
   if (can_transit)
   {
      automaton_data->syn_ack_table.update_entry(len, dir, ts);
   } 
}

inline bool transition_from_syn_ack(RecordExtVPN_AUTOMATON *automaton_data, uint16_t len, const timeval& ts, uint8_t dir)
{
   return automaton_data->syn_table.check_range_for_presence(len, 12, !dir, ts);
}

void VPN_AUTOMATONPlugin::update_record(RecordExtVPN_AUTOMATON *automaton_data, const Packet &pkt)
{ 
   /**
    * 0 - client -> server
    * 1 - server -> client
    */
   uint8_t dir = pkt.source_pkt ? 0 : 1;
   uint16_t len = pkt.payload_len;
   timeval ts = pkt.ts;

   if ( !(MIN_PKT_SIZE <= len && len <= MAX_PKT_SIZE) ) return;

   bool reached_end_state = transition_from_syn_ack(automaton_data, len, ts, dir);

   if (reached_end_state) 
   {
      automaton_data->reset();
      if (automaton_data->syn_pkts_idx < SYN_RECORDS_NUM)
      {
         automaton_data->syn_pkts[automaton_data->syn_pkts_idx] = len;
         automaton_data->syn_pkts_idx += 1;
      }
      automaton_data->suspects += 1;
      return;
   }

   transition_from_syn(automaton_data, len, ts, dir);
   transition_from_init(automaton_data, len, ts, dir);
}

int VPN_AUTOMATONPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtVPN_AUTOMATON *automaton_data = new RecordExtVPN_AUTOMATON();
   rec.add_extension(automaton_data);

   update_record(automaton_data, pkt);
   return 0;
}

int VPN_AUTOMATONPlugin::post_update(Flow &rec, const Packet &pkt)
{
   RecordExtVPN_AUTOMATON *automaton_data = (RecordExtVPN_AUTOMATON *) rec.get_extension(RecordExtVPN_AUTOMATON::REGISTERED_ID);
   update_record(automaton_data, pkt);
   return 0;
}

double classes_ratio(uint8_t* syn_pkts, uint8_t size)
{
   uint8_t unique_members = 0;
   bool marked[size];
   for (uint8_t i = 0; i < size; ++i) marked[i] = false;
   for (uint8_t i = 0; i < size; ++i)
   {
      if (marked[i]) continue;
      uint8_t akt_pkt_size = syn_pkts[i];
      unique_members++;
      marked[i] = true;
      for (uint8_t j = i + 1; j < size; ++j)
      {
         if (marked[j]) continue;
         if (syn_pkts[j] == akt_pkt_size) marked[j] = true;
      }
   }

   return double(unique_members) / double(size); 
}

void VPN_AUTOMATONPlugin::pre_export(Flow &rec)
{
   //do not export pstats for small packets flows
   uint32_t packets = rec.src_packets + rec.dst_packets;
   if (packets <= 30) {
      rec.remove_extension(RecordExtVPN_AUTOMATON::REGISTERED_ID);
      return;
   }

   RecordExtVPN_AUTOMATON *automaton_data = (RecordExtVPN_AUTOMATON *) rec.get_extension(RecordExtVPN_AUTOMATON::REGISTERED_ID);
   const auto& suspects = automaton_data->suspects; 
   if (suspects < 3) return;
   if (double(packets)/double(suspects) > 2500) return;
   if (suspects < 15)
   {
      if (classes_ratio(automaton_data->syn_pkts, automaton_data->syn_pkts_idx) > 0.6) return;
   } 
   else if (suspects < 40)
   {
      if (classes_ratio(automaton_data->syn_pkts, automaton_data->syn_pkts_idx) > 0.4) return;
   }
   else
   {
      if (classes_ratio(automaton_data->syn_pkts, automaton_data->syn_pkts_idx) > 0.2) return;
   }

   automaton_data->possible_vpn = 1;
}

}

