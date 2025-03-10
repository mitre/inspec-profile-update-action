control 'SV-255983' do
  title 'The Arista MLS layer 2 switch must not use the default VLAN for management traffic.'
  desc 'Switches use the default VLAN (i.e., VLAN 1) for in-band management and to communicate with directly connected switches using Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP)—all untagged traffic. As a consequence, the default VLAN may unwisely span the entire network if not appropriately pruned. If its scope is large enough, the risk of compromise can increase significantly.'
  desc 'check', 'Verify the Arista MLS configuration for a Management_Network VRF instance globally on the switch with the following example:

switch(config)#sh run | sec vrf
ip name-server vrf default 192.168.10.20
!
vrf instance Management_Network
!
interface Ethernet12
   description MANAGEMENT NETWORK PORT
   no switchport
   vrf Management_Network
   ip address 10.10.40.254/30
!
ip routing vrf Management_Network 

If the VRF is not configured to prevent the default VLAN from being used to access the switch, this is a finding.'
  desc 'fix', 'Step 1: Configure the Arista MLS switch for a VRF instance for Management Network access by using the following commands:

switch(config)#vrf instance Management_Network
switch(config-vrf-Management_Network)#exit

Step 2: Configure the Ethernet port for VRF Management_Network and IP address for the management network traffic:

switch(config-if-Et12)#vrf Management_Network 
switch(config-if-Et12)#ip address 10.10.40.254/30
switch(config-if-Et12)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59659r882289_chk'
  tag severity: 'medium'
  tag gid: 'V-255983'
  tag rid: 'SV-255983r882291_rule'
  tag stig_id: 'ARST-L2-000200'
  tag gtitle: 'SRG-NET-000512-L2S-000010'
  tag fix_id: 'F-59602r882290_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
