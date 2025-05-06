control 'SV-221794' do
  title 'The Oracle Linux operating system must audit all uses of the open_by_handle_at syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "open_by_handle_at" syscall occur.

Check the file system rules in "/etc/audit/audit.rules" with the following commands:

# grep -iw open_by_handle_at /etc/audit/audit.rules

-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

If both the "b32" and "b64" audit rules are not defined for the "open_by_handle_at" syscall, this is a finding.

If the output does not produce a rule containing "-F exit=-EPERM", this is a finding.

If the output does not produce a rule containing "-F exit=-EACCES", this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "open_by_handle_at" syscall occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36311r602527_chk'
  tag severity: 'medium'
  tag gid: 'V-221794'
  tag rid: 'SV-221794r603260_rule'
  tag stig_id: 'OL07-00-030530'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-36275r602528_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-108431', 'V-99327']
  tag cci: ['CCI-002884', 'CCI-000172']
  tag nist: ['MA-4 (1) (a)', 'AU-12 c']
end
