control 'SV-38376' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'fix', 'Change the permissions of the syslog configuration file.
# chmod 0640 /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22453'
  tag rid: 'SV-38376r1_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'GEN005390'
  tag fix_id: 'F-31985r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
