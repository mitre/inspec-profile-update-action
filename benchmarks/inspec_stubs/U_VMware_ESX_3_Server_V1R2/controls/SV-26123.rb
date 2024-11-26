control 'SV-26123' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the syslog.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27756r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22454'
  tag rid: 'SV-26123r1_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'GEN005395'
  tag fix_id: 'F-26298r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
