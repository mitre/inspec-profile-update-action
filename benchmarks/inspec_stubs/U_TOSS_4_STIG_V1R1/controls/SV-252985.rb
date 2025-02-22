control 'SV-252985' do
  title 'Successful/unsuccessful uses of the "chage" command in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chage" command is used to change or view user password expiry information.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1." The AUID representation is an unsigned 32-bit integer, which equals "4294967295." The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "chage" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w chage /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chage" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56438r824277_chk'
  tag severity: 'medium'
  tag gid: 'V-252985'
  tag rid: 'SV-252985r824279_rule'
  tag stig_id: 'TOSS-04-030310'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-56388r824278_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
