control 'SV-216822' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

router msdp
 …
 …
 …
 peer 4.4.4.4
  remote-as 33
  maximum external-sa 555
 !
 peer 5.5.5.5
  remote-as 44
  maximum external-sa 555
 !
!

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the router to limit the amount of source-active messages it accepts from each peer.

RP/0/0/CPU0:R2(config)#router msdp
RP/0/0/CPU0:R2(config-msdp)#peer x.14.2.1
RP/0/0/CPU0:R2(config-msdp-peer)#maximum external-sa nnn
RP/0/0/CPU0:R2(config-msdp-peer)#exit
RP/0/0/CPU0:R2(config-msdp)#peer x.15.3.5
RP/0/0/CPU0:R2(config-msdp-peer)#maximum external-sa nnn
RP/0/0/CPU0:R2(config-msdp-peer)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18054r288840_chk'
  tag severity: 'low'
  tag gid: 'V-216822'
  tag rid: 'SV-216822r531087_rule'
  tag stig_id: 'CISC-RT-000940'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-18052r288841_fix'
  tag 'documentable'
  tag legacy: ['V-96851', 'SV-105989']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
