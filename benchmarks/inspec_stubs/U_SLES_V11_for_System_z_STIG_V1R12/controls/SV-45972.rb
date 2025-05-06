control 'SV-45972' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the rsyslog configuration file(s).
# ls -lL /etc/rsyslog.conf /etc/rsyslog.d

If the mode of the file is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the permissions of the rsyslog configuration file(s).
# chmod 0640 /etc/rsyslog.conf 
# chmod 0640 /etc/rsyslog.d/*.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43254r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22453'
  tag rid: 'SV-45972r1_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'GEN005390'
  tag fix_id: 'F-39337r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
