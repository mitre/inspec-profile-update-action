control 'SV-221782' do
  title 'The Oracle Linux operating system must audit all uses of the chmod, fchmod, and fchmodat syscalls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify the operating system generates audit records upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" syscalls.

Check the file system rules in "/etc/audit/audit.rules" with the following command:

# grep chmod /etc/audit/audit.rules

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "chmod", "fchmod", and "fchmodat" syscalls, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" syscalls.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36299r810482_chk'
  tag severity: 'medium'
  tag gid: 'V-221782'
  tag rid: 'SV-221782r810497_rule'
  tag stig_id: 'OL07-00-030410'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag fix_id: 'F-36263r810496_fix'
  tag satisfies: ['SRG-OS-000458-GPOS-00203', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000064-GPOS-00033']
  tag 'documentable'
  tag legacy: ['V-99303', 'SV-108407']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
