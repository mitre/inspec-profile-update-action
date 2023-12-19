control 'SV-26088' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial-of-Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the inetd configuration file.
# ls -lL /etc/inetd.conf
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the inetd.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27688r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22424'
  tag rid: 'SV-26088r1_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'GEN003745'
  tag fix_id: 'F-26278r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
