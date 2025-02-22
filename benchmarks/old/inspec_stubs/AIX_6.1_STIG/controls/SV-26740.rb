control 'SV-26740' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf
If the mode of the file is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the permissions of the syslog configuration file.
# chmod 0640 /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22453'
  tag rid: 'SV-26740r1_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'GEN005390'
  tag fix_id: 'F-23989r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
