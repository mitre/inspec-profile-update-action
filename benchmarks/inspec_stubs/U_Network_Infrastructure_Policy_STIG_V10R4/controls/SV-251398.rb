control 'SV-251398' do
  title 'Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping must be implemented within the network access layer.'
  desc %q(The last-hop router sends the multicast packet out the interface towards the LAN containing interested receivers. The default behavior for a Layer 2 switch is to forward all multicast traffic out every access switch port that belongs to the VLAN. IGMP snooping is a mechanism used by "Layer 3 aware" switches to maintain a Layer 2 multicast table by examining all IGMP join and leave messages (destined to the all router's multicast address 224.0.0.2) sent between hosts and the multicast routers on the LAN. This will enable the switch to only forward multicast packets out the access switch ports that have connected hosts that have subscribed to the multicast group, thereby reducing the load on the switching backplane as well as eliminating unwanted traffic to uninterested hosts.)
  desc 'check', 'Review the access switches connected to multicast last-hop routers to determine if IGMP snooping is enabled. The following are switch configuration examples with IGMP snooping enabled globally and on a per-VLAN basis:

Enable IGMP Snooping globally: ip igmp snooping

Enable IGMP Snooping for VLAN: ip igmp snooping vlan 7

If any switches within the ICAN access layer do not have IGMP or MLD snooping enabled, this is a finding.'
  desc 'fix', 'Configure the switch to implement IGMP or MLD snooping, ensuring multicast traffic for any given multicast group is forwarded to only those hosts that have joined the group.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54833r806147_chk'
  tag severity: 'low'
  tag gid: 'V-251398'
  tag rid: 'SV-251398r853659_rule'
  tag stig_id: 'NET2016'
  tag gtitle: 'NET2016'
  tag fix_id: 'F-54786r806148_fix'
  tag 'documentable'
  tag legacy: ['V-66393', 'SV-80883']
  tag cci: ['CCI-001095', 'CCI-001549', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'AC-4', 'SC-5 a']
end
