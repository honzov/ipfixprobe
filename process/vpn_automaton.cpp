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

int VPN_AUTOMATONPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int VPN_AUTOMATONPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int VPN_AUTOMATONPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int VPN_AUTOMATONPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void VPN_AUTOMATONPlugin::pre_export(Flow &rec)
{
}

}

