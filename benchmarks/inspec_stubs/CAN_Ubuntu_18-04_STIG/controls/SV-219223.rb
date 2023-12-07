control 'SV-219223' do
  title 'The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', "Verify the Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep shadow

-w /etc/shadow -p wa -k usergroup_modification

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the Ubuntu operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.

Add or update the following rule to "/etc/audit/rules.d/stig.rules":

-w /etc/shadow -p wa -k usergroup_modification

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20948r304997_chk'
  tag severity: 'medium'
  tag gid: 'V-219223'
  tag rid: 'SV-219223r853375_rule'
  tag stig_id: 'UBTU-18-010247'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag fix_id: 'F-20947r304998_fix'
  tag satisfies: ['SRG-OS-000476-GPOS-00221', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000239-GPOS-00089']
  tag 'documentable'
  tag legacy: ['SV-109777', 'V-100673']
  tag cci: ['CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
