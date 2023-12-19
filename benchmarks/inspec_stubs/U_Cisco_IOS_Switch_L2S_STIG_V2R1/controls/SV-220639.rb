control 'SV-220639' do
  title 'The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability.

UDLD is a Layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with UDLD enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the switch configuration to verify that UDLD is enabled globally or on a per-interface basis as shown in the examples below:

hostname SW2
…
…
…
udld enable

or

interface GigabitEthernet0/1
 udld port

Note: An alternative implementation when UDLD is not supported by connected device is to deploy a single member Link Aggregation Group (LAG) via IEEE 802.3ad Link Aggregation Control Protocol (LACP).

If the switch has fiber optic interconnections with neighbors and UDLD is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to enable UDLD to protect against one-way connections:

SW2(config)#udld enable

or

SW2(config)#int g0/1
SW2(config-if)#udld port'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22354r507963_chk'
  tag severity: 'medium'
  tag gid: 'V-220639'
  tag rid: 'SV-220639r539671_rule'
  tag stig_id: 'CISC-L2-000190'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-22343r507964_fix'
  tag 'documentable'
  tag legacy: ['SV-110249', 'V-101145']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
