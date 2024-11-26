control 'SV-80555' do
  title 'The HP FlexFabric Switch must have BPDU Guard enabled on all user-facing access ports.'
  desc 'If a rogue switch is introduced into the topology and transmits a Bridge Protocol Data Unit (BPDU) with a lower bridge priority than the existing root bridge, it will become the new root bridge and cause a topology change, rendering the network in a suboptimal state. The Spanning Tree Protocol (STP) PortFast BPDU guard enhancement allows network designers to enforce the STP domain borders and keep the active topology predictable. The devices behind the ports that have STP PortFast enabled are not able to influence the STP topology. At the reception of BPDUs, the BPDU guard operation disables the port that has PortFast configured. The BPDU guard transitions the port into errdisable state and sends a log message.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that BPDU Protection is enabled on all user-facing switch ports.

If the HP FlexFabric Switch has not enabled BPDU protection, this is a finding.

[HP] display stp
-------[CIST Global Info][Mode MSTP]-------
 Bridge ID           : 32768.7848-596a-6580
 Bridge times        : Hello 2s MaxAge 20s FwdDelay 15s MaxHops 20
 Root ID/ERPC        : 32768.7848-596a-6580, 0
 RegRoot ID/IRPC     : 32768.7848-596a-6580, 0
 RootPort ID         : 0.0
 BPDU-Protection     : Enabled
 Bridge Config-
 Digest-Snooping     : Disabled
 TC or TCN received  : 0
 Time since last TC  : 3 days 

interface GigabitEthernet1/0/1
 stp edged-port'
  desc 'fix', 'Configure the HP FlexFabric Switch to have BPDU Guard enabled on all user-facing switch ports.

[HP]stp bpdu-protection
[HP-GigabitEthernet1/0/1]stp edged-port'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66065'
  tag rid: 'SV-80555r1_rule'
  tag stig_id: 'HFFS-L2-000011'
  tag gtitle: 'SRG-NET-000362-L2S-000022'
  tag fix_id: 'F-72141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
