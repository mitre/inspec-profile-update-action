control 'SV-221146' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to limit the amount of source-active messages it accepts on a per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP switch, the switch must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the switch configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

ip msdp peer x.1.28.2 connect-source Ethernet2/1 remote-as nn
…
…
…
ip msdp sa-limit x.1.28.2 nnn

If the switch is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the switch to limit the amount of source-active messages it accepts from each peer.

SW1(config)# ip msdp sa-limit x.1.28.2 nnn
SW1(config)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22861r409927_chk'
  tag severity: 'low'
  tag gid: 'V-221146'
  tag rid: 'SV-221146r622190_rule'
  tag stig_id: 'CISC-RT-000940'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-22850r409928_fix'
  tag 'documentable'
  tag legacy: ['SV-111259', 'V-102303']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
