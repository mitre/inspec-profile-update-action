control 'SV-253038' do
  title 'Successful/unsuccessful uses of the "removexattr" system call in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). "Removexattr" is a system call that removes extended attributes.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1." The AUID representation is an unsigned 32-bit integer, which equals "4294967295." The audit system interprets "-1", "4294967295", and "unset" in the same way.'
  desc 'check', 'Verify if TOSS is configured to audit the execution of the "removexattr" system call, by running the following command:

$ sudo grep -w removexattr /etc/audit/audit.rules

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod 

If the command does not return all lines, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to audit the execution of the "removexattr" system call, by adding or updating the following lines to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod 

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56491r824784_chk'
  tag severity: 'medium'
  tag gid: 'V-253038'
  tag rid: 'SV-253038r824786_rule'
  tag stig_id: 'TOSS-04-031120'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-56441r824785_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
