control 'SV-80569' do
  title 'The HP FlexFabric Switch must enable Device Link Detection Protocol (DLDP) to protect against one-way connections.'
  desc 'In topologies where fiber optic interconnections are used, physical misconnections can occur that allow a link to appear to be up when there is a mismatched set of transmit/receive pairs. When such a physical misconfiguration occurs, protocols such as STP can cause network instability. Device Link Detection Protocol (DLDP) is a layer 2 protocol that can detect these physical misconfigurations by verifying that traffic is flowing bidirectionally between neighbors. Ports with DLDP enabled periodically transmit packets to neighbor devices. If the packets are not echoed back within a specific time frame, the link is flagged as unidirectional and the interface is shut down.'
  desc 'check', 'If any of the switch ports have fiber optic interconnections with neighbors, review the HP FlexFabric Switch configuration to verify that DLDP is enabled globally or on a per interface basis.

If the HP FlexFabric Switch has fiber optic interconnections with neighbors and DLDP is not enabled, this is a finding.

<HP> display dldp
DLDP global status : disable
DLDP interval : 5s
DLDP work-mode : enhance
DLDP authentication-mode : none
DLDP unidirectional-shutdown : auto
DLDP delaydown-timer : 1s
The number of enabled ports is 2.
[HP-Interface Ethernet1/1]
DLDP port state : advertisement
DLDP link state : up
The neighbor number of the port is 0.
[HP-Interface Ethernet1/2]
DLDP port state : advertisement
DLDP link state : up
The neighbor number of the port is 0.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enable Device Link Detection Protocol (DLDP) to protect against one-way connections.

[HP]dldp global enable

[HP-Ten-GigabitEthernet1/0/47]dldp enable'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66723r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66079'
  tag rid: 'SV-80569r1_rule'
  tag stig_id: 'HFFS-L2-000021'
  tag gtitle: 'SRG-NET-000512-L2S-000004'
  tag fix_id: 'F-72155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
