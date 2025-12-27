control 'SV-206664' do
  title 'The layer 2 switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. UDLD is a layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with UDLD enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the switch configuration to verify that UDLD is enabled globally or on a per interface basis. 

If the switch has fiber optic interconnections with neighbors and UDLD is not enabled, this is a finding.'
  desc 'fix', 'Configure the switch to enable Unidirectional Link Detection (UDLD) to protect against one-way connections.

Note: UDLD is a Cisco-proprietary protocol.  However, other switch vendors, such as 3Com, Extreme, and D-Link, have similar functionality in their products, respectively: Device Link Detection Protocol (DLDP), Extreme Link Status Monitoring (ELSM), and D-Link Unidirectional Link Detection (DULD).'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6922r298422_chk'
  tag severity: 'medium'
  tag gid: 'V-206664'
  tag rid: 'SV-206664r539566_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000004'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6922r539565_fix'
  tag 'documentable'
  tag legacy: ['SV-76685', 'V-62195']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
