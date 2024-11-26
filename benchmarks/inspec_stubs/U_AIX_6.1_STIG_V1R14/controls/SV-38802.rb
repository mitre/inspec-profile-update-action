control 'SV-38802' do
  title 'The system must not send IPv4 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts a more direct route exists for a particular destination.  These messages contain information from the system's route table possibly revealing  portions of the network topology."
  desc 'check', '# /usr/sbin/no -o ipsendredirects
If the value is not 0,  this is a finding.'
  desc 'fix', '#/usr/sbin/no  -p -o ipsendredirects=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37258r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22417'
  tag rid: 'SV-38802r1_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'GEN003610'
  tag fix_id: 'F-32499r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
