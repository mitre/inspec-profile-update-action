control 'SV-216732' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.'
  desc 'To reduce any risk of a denial of service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

ip msdp peer x.1.28.2 remote-as nn
ip msdp sa-filter in 10.1.28.2 list MSDP_SA_FILTER
ip msdp sa-limit X.1.28.2 nnn

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the router to limit the amount of source-active messages it accepts from each peer.

R8(config)#ip msdp sa-limit x.1.28.2 nnn'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17965r288138_chk'
  tag severity: 'low'
  tag gid: 'V-216732'
  tag rid: 'SV-216732r531086_rule'
  tag stig_id: 'CISC-RT-000940'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-17963r288139_fix'
  tag 'documentable'
  tag legacy: ['V-97037', 'SV-106175']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
