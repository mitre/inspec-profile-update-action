control 'SV-255981' do
  title 'The Arista MLS layer 2 switch must not have the default VLAN assigned to any host-facing switch ports.'
  desc 'In a VLAN-based network, switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with other networking devices using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Review the Arista MLS switch configurations and verify no access switch ports have been assigned membership to the default VLAN (i.e., VLAN 1).
 
switch(config)#sh vlan
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                                              
8     VLAN0008                        active    Cpu
25    VLAN0025                       active    Cpu
100   VLAN0100                      active    Cpu
1000  VLAN1000                     active    Eth1, Eth2

If access switch ports are assigned to the default VLAN, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to remove the assignment of the default VLAN from all access switch ports.

Step 1: Configure the Default VLAN 1 to shut down by using the following command:

switch:(config#)interface vlan 1
switch(config-int-vlan1)#shutdown

Step 2: Configure all access switch ports to be placed in a VLAN other than the default (1):

switch(config)#interface ethernet 8
switch(config-eth8)#switchport access vlan 1000
switch(config-eth8)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59657r882283_chk'
  tag severity: 'medium'
  tag gid: 'V-255981'
  tag rid: 'SV-255981r882285_rule'
  tag stig_id: 'ARST-L2-000180'
  tag gtitle: 'SRG-NET-000512-L2S-000008'
  tag fix_id: 'F-59600r882284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
