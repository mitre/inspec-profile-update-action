control 'SV-38375' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36620r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22454'
  tag rid: 'SV-38375r1_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'GEN005395'
  tag fix_id: 'F-31987r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
