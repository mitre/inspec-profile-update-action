control 'SV-220689' do
  title 'The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. UDLD is a layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with UDLD enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the switch configuration to verify that either UDLD is enabled globally or not explicitly disabled on a per interface basis as shown in the examples below.

hostname SW1
…
…
…
feature udld

or

interface GigabitEthernet0/3
udld disabled

Note: By default, UDLD is enabled on all interfaces with fiber optic connections. An alternative implementationwhen UDLD is not supported by connected device is to deploy a single member Link Aggregation Group (LAG) via IEEE 802.3ad Link Aggregation Control Protocol (LACP).

If the switch has fiber optic interconnections with neighbors and UDLD is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to enable Unidirectional Link Detection (UDLD) to protect against one-way connections.

SW1(config)# feature udld'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22404r917684_chk'
  tag severity: 'medium'
  tag gid: 'V-220689'
  tag rid: 'SV-220689r917685_rule'
  tag stig_id: 'CISC-L2-000190'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-22393r539119_fix'
  tag 'documentable'
  tag legacy: ['SV-110353', 'V-101249']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
