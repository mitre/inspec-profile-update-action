control 'SV-37709' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'fix', 'Change the permissions of the syslog or rsyslog configuration file.
# chmod 0640 /etc/syslog.conf   
Or:
# chmod 0640 /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22453'
  tag rid: 'SV-37709r2_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'GEN005390'
  tag fix_id: 'F-32082r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
