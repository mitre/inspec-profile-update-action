control 'SV-227577' do
  title 'Successful and unsuccessful logins and logouts must be logged.'
  desc 'Monitoring and recording successful and unsuccessful logins assist in tracking unauthorized access to the system.  Without this logging, the ability to track unauthorized activity to specific user accounts may be diminished.'
  desc 'check', 'Determine if successful logons are being logged.
# last | more

Determine if unsuccessful logons are being logged.
# more /var/adm/loginlog

If the commands do not return successful and unsuccessful logins, this is a finding.

Check the syslog daemon configuration for authentication logging.
# egrep "auth\\.(info|debug)" /etc/syslog.conf
If there are no entries in syslog for the auth service,  this is a finding.'
  desc 'fix', 'Verify that login logs are handled correctly in the /etc/syslog.conf file.   Edit the /etc/syslog.conf file and add one of the entries below.

auth.debug    /var/log/authlog
OR 
auth.*    /var/log/authlog

Verify that service startup scripts for syslog and utmp (if present) are enabled.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36442r602929_chk'
  tag severity: 'medium'
  tag gid: 'V-227577'
  tag rid: 'SV-227577r603266_rule'
  tag stig_id: 'GEN000440'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-36406r602930_fix'
  tag 'documentable'
  tag legacy: ['V-765', 'SV-27080']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
