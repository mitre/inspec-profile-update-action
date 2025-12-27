control 'SV-45755' do
  title 'The system must log informational authentication data.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.'
  desc 'check', "Check /etc/rsyslog.conf and verify the auth facility is logging both the notice and info level messages by:

# grep “auth.notice” /etc/rsyslog.conf
# grep “auth.info” /etc/rsyslog.conf
or
# grep 'auth.*' /etc/rsyslog.conf

If auth.* is not found, and either auth.notice or auth.info is not found, this is a finding."
  desc 'fix', 'Edit /etc/rsyslog.conf and add local log destinations for auth.* or both auth.notice and auth.info.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43108r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12004'
  tag rid: 'SV-45755r1_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'GEN003660'
  tag fix_id: 'F-39154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
