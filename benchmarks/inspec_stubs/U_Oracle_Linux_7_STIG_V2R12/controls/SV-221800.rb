control 'SV-221800' do
  title 'The Oracle Linux operating system must audit all uses of the setfiles command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "setfiles" command occur.

Check the file system rule in "/etc/audit/audit.rules" with the following command:

$ sudo grep -w "/usr/sbin/setfiles" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "setfiles" command occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23515r860877_chk'
  tag severity: 'medium'
  tag gid: 'V-221800'
  tag rid: 'SV-221800r860879_rule'
  tag stig_id: 'OL07-00-030590'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-23504r860878_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209']
  tag 'documentable'
  tag legacy: ['V-99339', 'SV-108443']
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
