control 'SV-248802' do
  title 'OL 8 must generate audit records for any attempted modifications to the "lastlog" file.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 
 
DoD has defined the list of events for which OL 8 will provide an audit record generation capability as the following: 
 
1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels); 
 
2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; 
 
3) All account creations, modifications, disabling, and terminations; and 
 
4) All kernel module load, unload, and restart actions.

'
  desc 'check', 'Verify OL 8 generates an audit record for any attempted modifications to the "lastlog" file by running the following command to check the file system rules in "/etc/audit/audit.rules": 
 
$ sudo grep -w lastlog /etc/audit/audit.rules 
 
-w /var/log/lastlog -p wa -k logins 
 
If the command does not return a line or the line is commented out, this is a finding.  
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any attempted modifications to the "lastlog" file by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file: 
 
-w /var/log/lastlog -p wa -k logins 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52236r779970_chk'
  tag severity: 'medium'
  tag gid: 'V-248802'
  tag rid: 'SV-248802r853835_rule'
  tag stig_id: 'OL08-00-030600'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52190r779971_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
