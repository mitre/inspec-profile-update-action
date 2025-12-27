control 'SV-255971' do
  title 'The Arista MLS layer 2 switch must have BPDU Guard enabled on all switch ports connecting to access layer switches and hosts.'
  desc 'If a rogue switch is introduced into the topology and transmits a Bridge Protocol Data Unit (BPDU) with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state. The STP PortFast BPDU guard enhancement allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind the ports that have STP PortFast enabled are not able to influence the STP topology. At the reception of BPDUs, the BPDU guard operation disables the port that has PortFast configured. The BPDU guard transitions the port into a disabled state and sends a log message.'
  desc 'check', 'Review the Arista MLS to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports.

switch#show run | section bpdu
interface Ethernet37
   spanning-tree bpduguard enable

If the Arista MLS switch has not enabled BPDU Guard, this is a finding.'
  desc 'fix', 'The Arista MLS switch provides the capability to configure "spanning-tree bpduguard". Configure the Ethernet interface commands:

config 
interface Ethernet[X] 
switch(config)#interface ethernet [X]
switch(config-if-Et[X])#spanning-tree bpduguard enabled
switch(config-if-Et[X])'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59647r882253_chk'
  tag severity: 'medium'
  tag gid: 'V-255971'
  tag rid: 'SV-255971r882255_rule'
  tag stig_id: 'ARST-L2-000060'
  tag gtitle: 'SRG-NET-000362-L2S-000022'
  tag fix_id: 'F-59590r882254_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
