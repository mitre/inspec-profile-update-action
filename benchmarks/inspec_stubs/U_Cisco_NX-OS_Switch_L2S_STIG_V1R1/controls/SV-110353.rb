control 'SV-110353' do
  title 'The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. UDLD is a layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with UDLD enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the switch configuration to verify that UDLD is enabled globally or on a per interface basis as shown in the examples below.

Step 1: Verify that the UDLD feature has been enabled as shown in the example below:

hostname SW1
…
…
…
feature udld

Step 2: Verify that UDLD has not been disabled on any fiber optic interfaces as shown in the example below:

interface GigabitEthernet0/3
udld disabled

Note: By default, UDLD is enabled on all interfaces with fiber optic connections. An alternative implementation when UDLD is not supported by connected device is to deploy a single member Link Aggregation Group (LAG) via IEEE 802.3ad Link Aggregation Control Protocol (LACP).

If the switch has fiber optic interconnections with neighbors and UDLD is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to enable Unidirectional Link Detection (UDLD) to protect against one-way connections.

SW1(config)# feature udld'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100129r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101249'
  tag rid: 'SV-110353r1_rule'
  tag stig_id: 'CISC-L2-000190'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-106953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
