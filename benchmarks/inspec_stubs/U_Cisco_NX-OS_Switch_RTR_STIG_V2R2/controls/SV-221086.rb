control 'SV-221086' do
  title 'The Cisco switch must be configured to log all packets that have been dropped at interfaces via an ACL.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review all ACLs used to filter traffic and verify that packets being dropped are logged as shown in the configuration below:

ip access-list EXTERNAL_ACL
 10 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 20 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 30 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
…
 …
 …
90 deny ip any any log

If packets being dropped at an interface are not logged, this is a finding.'
  desc 'fix', 'Configure ACLs to log packets that are dropped as shown in the example below:

SW1(config)# ip access-list EXTERNAL_ACL
SW1(config-acl)# 90 deny ip any any log
SW1(config-acl)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22801r409747_chk'
  tag severity: 'low'
  tag gid: 'V-221086'
  tag rid: 'SV-221086r622190_rule'
  tag stig_id: 'CISC-RT-000200'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-22790r409748_fix'
  tag 'documentable'
  tag legacy: ['SV-110991', 'V-101887']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
