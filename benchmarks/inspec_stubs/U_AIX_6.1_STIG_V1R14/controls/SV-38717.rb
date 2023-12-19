control 'SV-38717' do
  title 'The system must not have the systat service active.'
  desc 'The systat daemon allows remote users to see the running process and who is running them.  This may aid in information collection for an attack and weaken the security posture of the system.'
  desc 'check', 'Check the /etc/inetd.conf file for active systat service.

#grep systat /etc/inetd.conf | grep -v \\#

If the systat service is enabled,  this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out systat the service line. 

Restart the inetd service.   

# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29513'
  tag rid: 'SV-38717r1_rule'
  tag stig_id: 'GEN009290'
  tag gtitle: 'GEN009290'
  tag fix_id: 'F-33071r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
