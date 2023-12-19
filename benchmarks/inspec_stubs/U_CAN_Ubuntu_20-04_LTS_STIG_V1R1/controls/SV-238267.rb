control 'SV-238267' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the lchown system call.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "lchown" system call. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep lchown 
 
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -k perm_chng 
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Notes: 
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "lchown" system call. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules": 
 
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng 
 
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41477r653974_chk'
  tag severity: 'medium'
  tag gid: 'V-238267'
  tag rid: 'SV-238267r653976_rule'
  tag stig_id: 'UBTU-20-010151'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-41436r653975_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
