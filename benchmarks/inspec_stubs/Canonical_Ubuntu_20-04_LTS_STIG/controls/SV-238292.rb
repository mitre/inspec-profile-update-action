control 'SV-238292' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the usermod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w usermod 
 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "usermod" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41502r654049_chk'
  tag severity: 'medium'
  tag gid: 'V-238292'
  tag rid: 'SV-238292r654051_rule'
  tag stig_id: 'UBTU-20-010176'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-41461r654050_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
