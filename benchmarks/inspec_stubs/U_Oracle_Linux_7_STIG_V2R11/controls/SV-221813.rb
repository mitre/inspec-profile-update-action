control 'SV-221813' do
  title 'The Oracle Linux operating system must audit all uses of the mount command and syscall.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "mount" command and syscall occur.

Check that the following system call is being audited by performing the following series of commands to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "mount" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

If both the "b32" and "b64" audit rules are not defined for the "mount" syscall, this is a finding.

If the use of the "mount" command and syscall are not being audited, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "mount" command and syscall occur.

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36314r860880_chk'
  tag severity: 'medium'
  tag gid: 'V-221813'
  tag rid: 'SV-221813r860882_rule'
  tag stig_id: 'OL07-00-030740'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-36278r860881_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-108469', 'V-99365']
  tag cci: ['CCI-000135', 'CCI-002884']
  tag nist: ['AU-3 (1)', 'MA-4 (1) (a)']
end
