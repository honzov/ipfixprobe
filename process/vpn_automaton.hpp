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
#include <sstream>
#include <cassert>

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


#define SYN_RECORDS_NUM 100
#define PKT_TABLE_SIZE 91
#define MIN_PKT_SIZE 60
#define MAX_PKT_SIZE 150
#define MAX_TIME_WINDOW 3000000 // in microseconds

using dir_t = uint8_t;

struct pkt_entry 
{
   timeval ts_dir1;
   timeval ts_dir2;

   void reset()
   {
      ts_dir1.tv_sec = 0;
      ts_dir1.tv_usec = 0;
      ts_dir2.tv_sec = 0;
      ts_dir2.tv_usec = 0;
   }

   timeval& get_time(dir_t dir)
   {
      if (dir == 1)
      {
         return ts_dir1;
      } 
      else 
      {
         return ts_dir2;
      }
   }

   pkt_entry()
   {
      reset();
   }
};

struct pkt_table
{
   pkt_entry table_[PKT_TABLE_SIZE];

   void reset()
   {
      for (int i = 0; i < PKT_TABLE_SIZE; ++i)
      {
         table_[i].reset();
      }
   }

   bool check_range_for_presence(uint16_t len, uint8_t down_by, dir_t dir, const timeval& ts_to_compare)
   {
      int8_t idx = get_idx_from_len(len);
      // if ( !(0 <= idx && idx < PKT_TABLE_SIZE) ) std::cout << "out:" << (int)idx << std::endl;
      for (int8_t i = std::max(idx - down_by, 0); i <= idx; ++i)
      {
         if (entry_is_present(i, dir, ts_to_compare)) return true;
      }
      return false;
   }

   void update_entry(uint16_t len, dir_t dir, timeval ts)
   {
      int8_t idx = get_idx_from_len(len);
      // if ( !(0 <= idx && idx < PKT_TABLE_SIZE) ) std::cout << "out:" << (int)idx << std::endl;
      if (dir == 1)
      {
         table_[idx].ts_dir1 = ts;
      } 
      else 
      {
         table_[idx].ts_dir2 = ts;
      }
   }

   private:
   inline int8_t get_idx_from_len(uint16_t len)
   {
      return std::max(int(len) - MIN_PKT_SIZE, 0);
   }

   inline bool time_in_window(const timeval& ts_now, const timeval& ts_old)
   {
      long diff_secs = ts_now.tv_sec - ts_old.tv_sec;
      long diff_micro_secs = ts_now.tv_usec - ts_old.tv_usec;

      diff_micro_secs += diff_secs * 1000000;
      if (diff_micro_secs > MAX_TIME_WINDOW) return false;
      return true;
   }

   inline bool entry_is_present(int8_t idx, dir_t dir, const timeval& ts_to_compare)
   {
      timeval& ts = table_[idx].get_time(dir);
      if (time_in_window(ts_to_compare, ts))
      {
         return true;
      } 
      return false;
   }
};

/**
 * \brief Flow record extension header for storing parsed VPN_AUTOMATON data.
 */
struct RecordExtVPN_AUTOMATON : public RecordExt {
   static int REGISTERED_ID;

   uint8_t possible_vpn {0}; // fidelity of this flow beint vpn
   uint64_t suspects {0};
   uint8_t syn_pkts_idx {0};
   uint8_t syn_pkts[SYN_RECORDS_NUM];

   pkt_table syn_table{};
   pkt_table syn_ack_table{};

   RecordExtVPN_AUTOMATON() : RecordExt(REGISTERED_ID){}

   void reset ()
   {
      syn_table.reset();
      syn_ack_table.reset();
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

   std::string get_text() const 
   {
      std::ostringstream out; 
      out << "Result:" << (int)possible_vpn << std::endl; 
      return out.str();
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

   void update_record(RecordExtVPN_AUTOMATON *automaton_data, const Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_VPN_AUTOMATON_HPP */

