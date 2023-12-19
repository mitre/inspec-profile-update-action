control 'SV-255970' do
  title 'The Arista MLS switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.'
  desc 'Spanning Tree Protocol (STP) does not provide any means for the network administrator to securely enforce the topology of the switched network. Any switch can be the root bridge in a network. However, a more optimal forwarding topology places the root bridge at a specific predetermined location. With the standard STP, any bridge in the network with a lower bridge ID takes the role of the root bridge. The administrator cannot enforce the position of the root bridge but can set the root bridge priority to 0 in an effort to secure the root bridge position.'
  desc 'check', 'Review the Arista MLS switch topology as well as the configuration to verify that root guard is enabled on switch ports facing switches that are downstream from the root bridge.

Example:
switch#sh run | sec guard root
interface Ethernet37
   spanning-tree guard root 

If the Arista MLS switch has not enabled guard root on all ports connecting to the access layer where the root bridge must not appear, this is a finding.'
  desc 'fix', 'The Arista MLS switch must be configured for spanning-tree guard root mode on all ports connecting to the access layer interface.

Configure Arista MLS switch Ethernet interface with the following commands:

switch#config 
switch(config)interface Ethernet[X] 
switch(config-if-Et[X])#spanning-tree guard root
switch(config-if-Et[X])#exit 
!'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59646r882250_chk'
  tag severity: 'low'
  tag gid: 'V-255970'
  tag rid: 'SV-255970r882252_rule'
  tag stig_id: 'ARST-L2-000050'
  tag gtitle: 'SRG-NET-000362-L2S-000021'
  tag fix_id: 'F-59589r882251_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
