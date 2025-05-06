control 'SV-248755' do
  title 'The OL 8 audit system must be configured to audit any use of the "setxattr" system call.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). "Setxattr" is a system call used to set an extended attribute value. 
 
When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify if OL 8 is configured to audit the execution of the "setxattr" system call by running the following command: 
 
$ sudo grep -w setxattr /etc/audit/audit.rules 
 
a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod 
a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod 
 
-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod 
 
If the command does not return all lines or the lines are commented out, this is a finding.  
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure OL 8 to audit the execution of the "setxattr" system call by adding or updating the following lines to "/etc/audit/rules.d/audit.rules": 
 
a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod 
a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod 
 
-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52189r779829_chk'
  tag severity: 'medium'
  tag gid: 'V-248755'
  tag rid: 'SV-248755r779831_rule'
  tag stig_id: 'OL08-00-030270'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52143r779830_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
