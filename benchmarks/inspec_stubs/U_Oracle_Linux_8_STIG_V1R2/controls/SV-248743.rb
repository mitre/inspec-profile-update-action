control 'SV-248743' do
  title 'OL 8 must generate audit records for all account creation events that affect "/etc/gshadow".'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify OL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow". 
 
Check the auditing rules in "/etc/audit/audit.rules" with the following command: 
 
$ sudo grep /etc/gshadow /etc/audit/audit.rules 
 
-w /etc/gshadow -p wa -k identity 
 
If the command does not return a line or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure OL 8 to generate audit records for all account creations events that affect "/etc/gshadow". 
 
Add or update the following file system rule to "/etc/audit/rules.d/audit.rules": 
 
-w /etc/gshadow -p wa -k identity 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52177r779793_chk'
  tag severity: 'medium'
  tag gid: 'V-248743'
  tag rid: 'SV-248743r779795_rule'
  tag stig_id: 'OL08-00-030160'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-52131r779794_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002132', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'MA-4 (1) (a)']
end
