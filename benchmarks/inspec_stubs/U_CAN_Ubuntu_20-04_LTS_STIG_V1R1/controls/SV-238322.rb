control 'SV-238322' do
  title 'The Ubuntu operating system must generate records for successful/unsuccessful uses of delete_module syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the Ubuntu operating system is configured to audit the "delete_module" syscall by running the following command: 
 
$ sudo auditctl -l | egrep delete_module 
 
-a always,exit -F arch=b64 -S delete_module -F key=modules 
-a always,exit -F arch=b32 -S delete_module -F key=modules 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Notes: 
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the Ubuntu operating system to generate an audit event for any use of the "delete_module" system call. 
 
Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S delete_module -F key=modules 
-a always,exit -F arch=b64 -S delete_module -F key=modules 
 
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41532r654139_chk'
  tag severity: 'medium'
  tag gid: 'V-238322'
  tag rid: 'SV-238322r654141_rule'
  tag stig_id: 'UBTU-20-010302'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-41491r654140_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
