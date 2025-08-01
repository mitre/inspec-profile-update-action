control 'SV-204572' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the unlink syscall.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "unlink" syscall occur.

Check the file system rules in "/etc/audit/audit.rules" with the following commands:

# grep -iw unlink /etc/audit/audit.rules

-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -k delete

-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -k delete

If both the "b32" and "b64" audit rules are not defined for the "unlink" syscall, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "unlink" syscall occur.

Add the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -k delete

-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -k delete

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4696r462684_chk'
  tag severity: 'medium'
  tag gid: 'V-204572'
  tag rid: 'SV-204572r603261_rule'
  tag stig_id: 'RHEL-07-030910'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-4696r462685_fix'
  tag satisfies: ['SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['V-72205', 'SV-86829']
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
end
