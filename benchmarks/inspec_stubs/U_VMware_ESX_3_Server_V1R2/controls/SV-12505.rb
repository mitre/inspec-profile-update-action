control 'SV-12505' do
  title 'The system must log authentication informational data.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.'
  desc 'check', %q(Check /etc/syslog.conf and verify the auth facility is logging both the notice and info level messages by using one of the procedures below.

# grep "auth.notice" /etc/syslog.conf
# grep "auth.info" /etc/syslog.conf
OR
# grep 'auth.*' /etc/syslog.conf

If auth.* is not found, and either auth.notice or auth.info is not found, this is a finding.)
  desc 'fix', 'Edit /etc/syslog.conf and add local log destinations for auth.* or both auth.notice and auth.info.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7968r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12004'
  tag rid: 'SV-12505r2_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'GEN003660'
  tag fix_id: 'F-11264r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
