control 'SV-238311' do
  title 'The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlinkat system call.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the Ubuntu operating system generates audit records for any successful/unsuccessful use of unlinkat system call. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep unlinkat 
 
-a always,exit -F arch=b64  -S unlinkat -F auid>=1000 -F auid!=-1 -k delete 
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=-1 -k delete 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Notes: 
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate audit events for any successful/unsuccessful use of the unlinkat system call. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b64 -S unlinkat -Fauid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete 
 
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41521r654106_chk'
  tag severity: 'medium'
  tag gid: 'V-238311'
  tag rid: 'SV-238311r654108_rule'
  tag stig_id: 'UBTU-20-010268'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-41480r654107_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
