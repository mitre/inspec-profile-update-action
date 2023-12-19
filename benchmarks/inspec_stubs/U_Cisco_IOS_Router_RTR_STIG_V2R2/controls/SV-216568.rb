control 'SV-216568' do
  title 'The Cisco router must be configured to log all packets that have been dropped at interfaces via an ACL.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review all Access Control Lists(ACLs) used to filter traffic and verify that packets being dropped are logged as shown in the configuration below.

ip access-list extended INGRESS_FILTER
 permit tcp any any established
 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 permit tcp any host x.11.1.5 eq www
 permit icmp host x.11.1.1 host x.11.1.2 echo
 permit icmp any any echo-reply
 …
 …
 …
deny   ip any any log

If packets being dropped at interfaces are not logged, this is a finding.'
  desc 'fix', 'Configure ACLs to log  packets that are dropped as shown in the example below.

R5(config)#ip access-list extended INGRESS_FILTER
…
…
…
R5(config-ext-nacl)#deny ip any any log'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17803r287088_chk'
  tag severity: 'low'
  tag gid: 'V-216568'
  tag rid: 'SV-216568r531085_rule'
  tag stig_id: 'CISC-RT-000200'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-17799r287089_fix'
  tag 'documentable'
  tag legacy: ['SV-105675', 'V-96537']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
