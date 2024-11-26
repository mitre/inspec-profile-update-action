control 'SV-221795' do
  title 'The Oracle Linux operating system must audit all uses of the truncate syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "truncate" syscall occur.

Check the file system rules in "/etc/audit/audit.rules" with the following commands:

# grep -iw truncate /etc/audit/audit.rules

-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

If both the "b32" and "b64" audit rules are not defined for the "truncate" syscall, this is a finding.

If the output does not produce a rule containing "-F exit=-EPERM", this is a finding.

If the output does not produce a rule containing "-F exit=-EACCES", this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "truncate" syscall occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36312r602530_chk'
  tag severity: 'medium'
  tag gid: 'V-221795'
  tag rid: 'SV-221795r603260_rule'
  tag stig_id: 'OL07-00-030540'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-36276r602531_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['V-99329', 'SV-108433']
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
end
