control 'SV-204519' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the lchown syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "lchown" syscall occur.

Check the file system rules in "/etc/audit/audit.rules" with the following commands:

# grep -iw lchown /etc/audit/audit.rules

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "lchown" syscall, this is a finding.'
  desc 'fix', 'Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4643r462564_chk'
  tag severity: 'medium'
  tag gid: 'V-204519'
  tag rid: 'SV-204519r603261_rule'
  tag stig_id: 'RHEL-07-030390'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-4643r462565_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag legacy: ['V-72101', 'SV-86725']
  tag cci: ['CCI-000126', 'CCI-000172']
  tag nist: ['AU-2 c', 'AU-12 c']
end
