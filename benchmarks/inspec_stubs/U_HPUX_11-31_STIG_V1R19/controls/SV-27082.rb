control 'SV-27082' do
  title 'Successful and unsuccessful logins and logouts must be logged.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.  Without this logging, the ability to track unauthorized activity to specific user accounts may be diminished.'
  desc 'check', 'List the logged successful logons to determine if successful logons are being logged.

# last -R | more

List the logged unsuccessful logons to determine if unsuccessful logons are being logged.

# lastb -R | more

If logs do not contain successful and unsuccessful logins, this is a finding.'
  desc 'fix', %q(Verify that login logs are handled correctly in the /etc/syslog.conf file. Verify that service startup scripts for syslog and (w/b)tmp (if present) are enabled. NOTE:  Also examine the syslog.conf file for any references to remote log hosts if last/lastb produce no results.

# cat /etc/syslog.conf | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | grep -v '^#' | grep "\@")
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-27995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-765'
  tag rid: 'SV-27082r1_rule'
  tag stig_id: 'GEN000440'
  tag gtitle: 'GEN000440'
  tag fix_id: 'F-31505r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
