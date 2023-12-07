control 'SV-238279' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chsh command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chsh" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep chsh 
 
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Notes: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chsh" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41489r654010_chk'
  tag severity: 'medium'
  tag gid: 'V-238279'
  tag rid: 'SV-238279r654012_rule'
  tag stig_id: 'UBTU-20-010163'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-41448r654011_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
