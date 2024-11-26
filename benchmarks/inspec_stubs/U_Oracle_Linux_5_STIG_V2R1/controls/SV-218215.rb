control 'SV-218215' do
  title 'Successful and unsuccessful logins and logouts must be logged.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.  Without this logging, the ability to track unauthorized activity to specific user accounts may be diminished.'
  desc 'check', 'Determine if all logon attempts are being logged.

Procedure:
Verify successful logins are being logged:
# last -R | more 
If the command does not return successful logins, this is a finding.

Verify if unsuccessful logons are being logged: 
# lastb -R | more
If the command does not return unsuccessful logins, this is a finding.'
  desc 'fix', 'Make sure the collection files exist.
Procedure:
If there are no successful logins being returned from the "last" command, create /var/log/wtmp:
# touch /var/log/wtmp

If there are no unsuccessful logins being returned from the "lastb" command, create /var/log/btmp:
# touch /var/log/btmp'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19690r553982_chk'
  tag severity: 'medium'
  tag gid: 'V-218215'
  tag rid: 'SV-218215r603259_rule'
  tag stig_id: 'GEN000440'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19688r553983_fix'
  tag 'documentable'
  tag legacy: ['V-765', 'SV-63363']
  tag cci: ['CCI-000126', 'CCI-000366']
  tag nist: ['AU-2 c', 'CM-6 b']
end
