control 'SV-227810' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29972r489787_chk'
  tag severity: 'medium'
  tag gid: 'V-227810'
  tag rid: 'SV-227810r603266_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-29960r489788_fix'
  tag 'documentable'
  tag legacy: ['V-12004', 'SV-12505']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
