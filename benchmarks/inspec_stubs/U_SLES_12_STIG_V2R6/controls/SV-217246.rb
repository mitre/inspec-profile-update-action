control 'SV-217246' do
  title 'The SUSE operating system must generate audit records for all modifications to the tallylog file must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record when all modifications to the "tallylog" file occur.

Check that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i tallylog /etc/audit/audit.rules

-w /var/log/tallylog -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for any all modifications to the "tallylog" file occur. 

Add or update the following rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/tallylog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18474r369894_chk'
  tag severity: 'medium'
  tag gid: 'V-217246'
  tag rid: 'SV-217246r603262_rule'
  tag stig_id: 'SLES-12-020650'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18472r369895_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag legacy: ['SV-92101', 'V-77405']
  tag cci: ['CCI-000172', 'CCI-000169', 'CCI-000130', 'CCI-002884']
  tag nist: ['AU-12 c', 'AU-12 a', 'AU-3 a', 'MA-4 (1) (a)']
end
