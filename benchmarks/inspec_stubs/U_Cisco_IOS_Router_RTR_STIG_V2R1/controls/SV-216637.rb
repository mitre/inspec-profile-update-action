control 'SV-216637' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

ip msdp peer x.1.28.2 remote-as nn
ip msdp sa-filter in 10.1.28.2 list MSDP_SA_FILTER
ip msdp sa-limit X.1.28.2 nnn

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the router to limit the amount of source-active messages it accepts from each peer.

R8(config)#ip msdp sa-limit x.1.28.2 nnn'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17872r287280_chk'
  tag severity: 'low'
  tag gid: 'V-216637'
  tag rid: 'SV-216637r531085_rule'
  tag stig_id: 'CISC-RT-000940'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-17868r287281_fix'
  tag 'documentable'
  tag legacy: ['V-96673', 'SV-105811']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
