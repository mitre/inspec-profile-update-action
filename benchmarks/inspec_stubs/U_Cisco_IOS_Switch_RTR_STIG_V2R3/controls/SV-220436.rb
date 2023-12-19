control 'SV-220436' do
  title 'The Cisco switch must be configured to log all packets that have been dropped at interfaces via an access control list (ACL).'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review all ACLs used to filter traffic and verify that packets being dropped at interfaces via an ACL are logged as shown in the configuration below: 

ip access-list extended INGRESS_FILTER 
 permit tcp any any established 
 permit tcp any host x.11.1.5 eq www 
 permit icmp host x.11.1.1 host x.11.1.2 echo 
 permit icmp any any echo-reply 
… 
 … 
 … 
deny ip any any log 

If packets being dropped are not logged, this is a finding.'
  desc 'fix', 'Configure ACLs to log packets that are dropped as shown in the example below: 

SW1(config)#ip access-list extended INGRESS_FILTER 
… 
… 
… 
SW1(config-ext-nacl)#deny ip any any log'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22151r508393_chk'
  tag severity: 'low'
  tag gid: 'V-220436'
  tag rid: 'SV-220436r622190_rule'
  tag stig_id: 'CISC-RT-000200'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-22140r508394_fix'
  tag 'documentable'
  tag legacy: ['SV-110719', 'V-101615']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
