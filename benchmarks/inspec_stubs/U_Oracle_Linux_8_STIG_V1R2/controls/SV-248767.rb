control 'SV-248767' do
  title 'OL 8 must generate audit records for any use of the "setsebool" command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "setsebool" command sets the current state of a particular SELinux boolean or a list of booleans to a given value.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify OL 8 is configured to audit the execution of the "setsebool" command by running the following command: 
 
$ sudo grep -w setsebool /etc/audit/audit.rules 
 
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update 
 
If the command does not return all lines or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure OL 8 to audit the execution of the "setsebool" command by adding or updating the following lines to "/etc/audit/rules.d/audit.rules": 
 
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52201r779865_chk'
  tag severity: 'medium'
  tag gid: 'V-248767'
  tag rid: 'SV-248767r779867_rule'
  tag stig_id: 'OL08-00-030316'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52155r779866_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
