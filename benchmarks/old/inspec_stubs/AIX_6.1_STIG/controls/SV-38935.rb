control 'SV-38935' do
  title 'Successful and unsuccessful logins and logouts must be logged.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.  Without this logging, the ability to track unauthorized activity to specific user accounts may be diminished.'
  desc 'check', 'Determine if successful logons are being logged.
# last | more
 
Determine if unsuccessful logons are being logged. 
# last -f /etc/security/failedlogin | more

If the commands do not return successful and unsuccessful logins, this is a finding.'
  desc 'fix', 'Edit /etc/syslog.conf and add local log destinations for auth.* or both auth.notice and auth.info. 

"auth.info /var/log/authlog"

Verify service startup scripts for syslog and utmp (if present) are enabled.  

# vi /etc/rc.tcpip
Check the syslogd service is not commented out.

Refresh syslogd.
#refresh -s syslogd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27996r1_chk'
  tag severity: 'medium'
  tag gid: 'V-765'
  tag rid: 'SV-38935r1_rule'
  tag stig_id: 'GEN000440'
  tag gtitle: 'GEN000440'
  tag fix_id: 'F-31630r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
