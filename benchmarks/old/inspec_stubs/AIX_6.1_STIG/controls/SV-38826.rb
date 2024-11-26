control 'SV-38826' do
  title 'The system must not send IPv6 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table that could reveal portions of the network topology."
  desc 'check', '# /usr/sbin/no -o ipsendredirects
If the value returned is not 0,  this is a finding.'
  desc 'fix', 'Configure the system to not send IPv6 ICMP redirects.  
# /usr/sbin/no -p -o ipsendredirects=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22551'
  tag rid: 'SV-38826r1_rule'
  tag stig_id: 'GEN007880'
  tag gtitle: 'GEN007880'
  tag fix_id: 'F-32349r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
