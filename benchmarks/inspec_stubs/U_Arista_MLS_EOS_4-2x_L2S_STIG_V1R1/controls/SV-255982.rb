control 'SV-255982' do
  title 'The Arista MLS layer 2 switch must have the default VLAN pruned from all trunk ports that do not require it.'
  desc 'The default VLAN (i.e., VLAN 1) is a special VLAN used for control plane traffic such as Spanning-Tree Protocol (STP), Dynamic Trunking Protocol (DTP), VLAN Trunking Protocol (VTP), and Port Aggregation Protocol (PAgP). VLAN 1 is enabled on all trunks and ports by default. With larger campus networks, care needs to be taken about the diameter of the STP domain for the default VLAN. Instability in one part of the network could affect the default VLAN, thereby influencing control-plane stability and therefore STP stability for all other VLANs.'
  desc 'check', 'Review the Arista MLS switch configuration and verify the default VLAN is pruned from trunk links that do not require it.

Step 1: Review the Arista MLS switch configuration by using the following commands to ensure the default VLAN 1 state is suspended:

switch(config)#vlan 1
switch(config-vlan-1)#sh act
vlan 
   !! STIG suspend vlan 1 #state suspend vlan 1
switch(config-vlan-1)#exit

Step 2: Review the configuration to ensure default VLAN 1 is pruned from any trunk active links by using the command "show vlan brief":

switch(config-vlan-4090)#
switch(config-vlan-4090)#sh vlan brie
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                             
8     VLAN0008                         active    Cpu
25    VLAN0025                        active    Cpu
100   VLAN0100                       active    Cpu
1000  VLAN1000                      active    
4090  VLAN4090                      active   

If the default VLAN state is not suspended and pruned from trunk links that should not be transporting frames for the VLAN, this is a finding.'
  desc 'fix', 'Best practice for VLAN-based networks is to configure Arista MLS switch to prune unnecessary trunk links from gaining access to the default VLAN and ensure frames belonging to the default VLAN do not traverse trunks not requiring frames from the VLAN.

Step 1: Configure the Arista MLS switch to ensure VLAN1 is pruned from all trunk and access ports that do not require it by using the following commands:

switch(config)#vlan 1
switch(config-vlan-1)#show active
switch(config-vlan-1)#sh act
vlan 
   !! STIG suspend vlan 1 #state suspend vlan 1
switch(config-vlan-1)#exit

Step 2: Configure the Arista MLS switch to allow VLAN trunking except default VLAN 1 and configure Ethernet port 1 to change the native VLAN to 1000.

switch(config)#interface e10
switch(config-eth1o)#switchport trunk native vlan 1000
switch(config-eth1)#switchport trunk allowed vlan except 1
 
Step 3: Alternatively, the Arista MLS switch can use trunk groups to determine which trunks service which VLANs:

switch(config)#vlan 1
switch(config-vlan-1)#trunk group DO_NOT_USE
switch(config-vlan-1)#sh act
vlan 
   !! STIG suspend vlan 1 #state suspend vlan 1
   trunk group DO_NOT_USE
hss474.10:51:12(config-vlan-1)#

Step 4: On Arista MLS switch, ensure any unnecessary trunk links have not gained access to default VLAN 1; this can be verified with the command "show vlan brief":

switch(config)#sh vlan brief
VLAN Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                             
8     VLAN0008                         active    Cpu
25    VLAN0025                        active    Cpu
100   VLAN0100                       active    Cpu
1000  VLAN1000                      active    Eth1, Eth15, Eth16, Eth17
4090  VLAN4090                      active    Eth2, Eth20, Eth32'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59658r882286_chk'
  tag severity: 'medium'
  tag gid: 'V-255982'
  tag rid: 'SV-255982r882288_rule'
  tag stig_id: 'ARST-L2-000190'
  tag gtitle: 'SRG-NET-000512-L2S-000009'
  tag fix_id: 'F-59601r882287_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
