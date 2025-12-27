control 'SV-46104' do
  title 'The system must use an appropriate reverse-path filter for IPv6 network traffic, if the system uses IPv6.'
  desc 'Reverse-path filtering provides protection against spoofed source addresses by causing the system to discard packets with source addresses for which the system has no route or if the route does not point towards the interface on which the packet arrived. Depending on the role of the system, reverse-path filtering may cause legitimate traffic to be discarded and, therefore, should be used with a more permissive mode or filter, or not at all. Whenever possible, reverse-path filtering should be used.'
  desc 'check', 'Reverse Path filtering for IPv6 is not implemented in SLES.'
  desc 'fix', 'If the system uses IPv6 use an appropriate reverse-path filter for IPV6 network traffic.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43362r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22552'
  tag rid: 'SV-46104r1_rule'
  tag stig_id: 'GEN007900'
  tag gtitle: 'GEN007900'
  tag fix_id: 'F-40350r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
