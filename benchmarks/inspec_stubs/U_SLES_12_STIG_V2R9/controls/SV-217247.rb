control 'SV-217247' do
  title 'The SUSE operating system must generate audit records for all modifications to the lastlog file.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record when all modifications to the "lastlog" file occur.

Check that the following is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i lastlog /etc/audit/audit.rules

-w /var/log/lastlog -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for any all modifications to the "lastlog" file occur. 

Add or update the following rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/lastlog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18475r369897_chk'
  tag severity: 'medium'
  tag gid: 'V-217247'
  tag rid: 'SV-217247r854141_rule'
  tag stig_id: 'SLES-12-020660'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18473r369898_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-92103', 'V-77407']
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
