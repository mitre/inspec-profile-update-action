control 'SV-234946' do
  title 'The SUSE operating system must generate audit records for all modifications to the tallylog file must generate an audit record.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record when all modifications to the "tallylog" file occur.

Check that the file is being audited by performing the following command:

> sudo auditctl -l | grep -w '/var/log/tallylog'

-w /var/log/tallylog -p wa -k logins

If the command does not return a line, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for any all modifications to the "tallylog" file occur. 

Add or update the following rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/tallylog -p wa -k logins

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38134r619107_chk'
  tag severity: 'medium'
  tag gid: 'V-234946'
  tag rid: 'SV-234946r622137_rule'
  tag stig_id: 'SLES-15-030470'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38097r619108_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-000130', 'CCI-000169', 'CCI-002884']
  tag nist: ['AU-12 c', 'AU-3 a', 'AU-12 a', 'MA-4 (1) (a)']
end
