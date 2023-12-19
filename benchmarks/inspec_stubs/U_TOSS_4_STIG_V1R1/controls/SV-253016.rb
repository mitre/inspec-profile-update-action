control 'SV-253016' do
  title 'Successful/unsuccessful uses of the ftruncate system call system call in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "truncate" and "ftruncate" system calls are used to truncate a file to a specified length.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1." The AUID representation is an unsigned 32-bit integer, which equals "4294967295." The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify TOSS generates an audit record when successful/unsuccessful attempts to use the "ftruncate" system call by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -iw ftruncate /etc/audit/audit.rules

-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

If the command does not return all lines, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ftruncate" system call by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56469r824370_chk'
  tag severity: 'medium'
  tag gid: 'V-253016'
  tag rid: 'SV-253016r824372_rule'
  tag stig_id: 'TOSS-04-030630'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-56419r824371_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
