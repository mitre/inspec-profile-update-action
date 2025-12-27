control 'SV-248766' do
  title 'OL 8 must generate audit records for any use of the "userhelper" command.'
  desc %q(Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "userhelper" command is not intended to be run interactively. "Userhelper" provides a basic interface to change a user's password, gecos information, and shell. The main difference between this program and its traditional equivalents (passwd, chfn, chsh) is that prompts are written to standard out to make it easy for a graphical user interface wrapper to interface to it as a child process.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.)
  desc 'check', 'Verify OL 8 is configured to audit the execution of the "userhelper" command by running the following command: 
 
$ sudo grep -w userhelper /etc/audit/audit.rules 
 
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update 
 
If the command does not return all lines or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure OL 8 to audit the execution of the "userhelper" command by adding or updating the following lines to "/etc/audit/rules.d/audit.rules": 
 
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52200r779862_chk'
  tag severity: 'medium'
  tag gid: 'V-248766'
  tag rid: 'SV-248766r779864_rule'
  tag stig_id: 'OL08-00-030315'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-52154r779863_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
