control 'SV-220067' do
  title 'The system must use an appropriate reverse-path filter for IPv6 network traffic, if the system uses IPv6.'
  desc 'Reverse-path filtering provides protection against spoofed source addresses by causing the system to discard packets with source addresses for which the system has no route or if the route does not point towards the interface on which the packet arrived. Depending on the role of the system, reverse-path filtering may cause legitimate traffic to be discarded and, therefore, should be used with a more permissive mode or filter, or not at all. Whenever possible, reverse-path filtering should be used.'
  desc 'check', 'Determine if the system uses a reverse-path filter for IPv6 network traffic. If it does not, this is a finding.'
  desc 'fix', 'Configure the system to use a reverse-path filter for IPv6 network traffic.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21776r485543_chk'
  tag severity: 'medium'
  tag gid: 'V-220067'
  tag rid: 'SV-220067r603265_rule'
  tag stig_id: 'GEN007900'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-21775r485544_fix'
  tag 'documentable'
  tag legacy: ['SV-26227', 'V-22552']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
