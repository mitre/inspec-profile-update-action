control 'SV-37710' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/syslog.conf   
Or:
# setfacl -- remove-all /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22454'
  tag rid: 'SV-37710r2_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'GEN005395'
  tag fix_id: 'F-32087r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
