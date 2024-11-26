control 'SV-765' do
  title 'Successful and unsuccessful logins and logouts must be logged.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.  Without this logging, the ability to track unauthorized activity to specific user accounts may be diminished.'
  desc 'check', 'Check the system logs for successful and unsuccessful logins.  If these events are not present in the logs, this is a finding.'
  desc 'fix', 'Verify the login logs are handled correctly in the /etc/syslog.conf file.
Verify the service startup scripts for syslog and utmp (if present) are enabled.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27079'
  tag rid: 'SV-765r2_rule'
  tag stig_id: 'GEN000440'
  tag gtitle: 'GEN000440'
  tag fix_id: 'F-24352r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
