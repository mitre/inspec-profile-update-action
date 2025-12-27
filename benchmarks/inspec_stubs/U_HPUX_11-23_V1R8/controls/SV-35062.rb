control 'SV-35062' do
  title 'The system must log authentication informational data.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.'
  desc 'check', %q(Check /etc/syslog.conf and verify the auth facility is logging both the notice and info (NOTE that auth.info includes auth.notice and the auth.debug includes both auth.info and auth.notice) level messages by:
# cat /etc/syslog.conf | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//' | grep -v "^#" | egrep -i "auth.info|auth.debug|auth.\*|\*.info|\*.debug"

If auth.* is not found, or auth.notice or auth.debug or *.info and *.debug are not found, this is a finding.)
  desc 'fix', 'Edit /etc/syslog.conf and add local log destinations for auth.*, auth.debug, auth.info, *.debug or *.info.

NOTE: In general and though not required, it is always advisable to explicitly declare auth.info or auth.debug entries rather than use the wildcard notation method.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36521r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12004'
  tag rid: 'SV-35062r1_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'GEN003660'
  tag fix_id: 'F-31881r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-3, ECAR-2, ECAR-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
