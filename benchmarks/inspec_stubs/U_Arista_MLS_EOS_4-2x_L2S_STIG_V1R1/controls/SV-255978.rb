control 'SV-255978' do
  title 'The Arista MLS layer 2 switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. UDLD is a layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with UDLD enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the Arista MLS switch configuration to verify that Loop Guard is enabled globally or on a per interface basis.

switch# sh run | sec spanning-tree
spanning-tree guard loop default

Or,

interface Ethernet6
    spanning-tree guard loop

If the switch has fiber optic interconnections with neighbors and Loop Guard is not enabled, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to enable Loop Guard to prevent Unidirectional Link Detection (UDLD) and to protect against one-way connections.

switch(config)#spanning-tree guard loop default
switch(config)#

Alternatively, configure Loop Guard on each interface:

switch(config-if-Eth6)# spanning-tree guard loop

Note: UDLD is a Cisco-proprietary protocol. However, other switch vendors, such as 3Com, Extreme, and D-Link, have similar functionality in their products, respectively: Device Link Detection Protocol (DLDP), Extreme Link Status Monitoring (ELSM), and D-Link Unidirectional Link Detection (DULD).'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59654r882274_chk'
  tag severity: 'medium'
  tag gid: 'V-255978'
  tag rid: 'SV-255978r882276_rule'
  tag stig_id: 'ARST-L2-000150'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-59597r882275_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
