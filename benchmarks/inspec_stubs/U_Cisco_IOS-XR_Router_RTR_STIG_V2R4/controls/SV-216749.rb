control 'SV-216749' do
  title 'The Cisco router must be configured to log all packets that have been dropped at interfaces via ACL.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review all ACLs used to filter traffic and verify that packets being dropped are logged as shown in the configuration below.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 25 deny icmp any host x.11.1.2 fragments log 
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log
 60 permit tcp any any established
 …
 …
 …
 140 deny ipv4 any any log 

If packets being dropped at interfaces are not logged, this is a finding.'
  desc 'fix', 'Configure ACLs to log  packets that are dropped as shown in the example below.

RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
…
…
…
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17981r288636_chk'
  tag severity: 'low'
  tag gid: 'V-216749'
  tag rid: 'SV-216749r531087_rule'
  tag stig_id: 'CISC-RT-000200'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-17979r288637_fix'
  tag 'documentable'
  tag legacy: ['SV-105843', 'V-96705']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
