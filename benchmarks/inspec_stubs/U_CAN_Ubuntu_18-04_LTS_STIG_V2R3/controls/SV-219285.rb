control 'SV-219285' do
  title 'The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the removexattr system call.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', "Verify the Ubuntu operating system generates audit records when successful/unsuccessful attempts to use removexattr system call.

Check the configured audit rules with the following commands:

# sudo auditctl -l | grep removexattr

-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -k perm_chng

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the audit system to generate audit records for successful/unsuccessful attempts to use removexattr system call.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21010r305183_chk'
  tag severity: 'medium'
  tag gid: 'V-219285'
  tag rid: 'SV-219285r610963_rule'
  tag stig_id: 'UBTU-18-010369'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-21009r305184_fix'
  tag satisfies: ['SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210']
  tag 'documentable'
  tag legacy: ['SV-109897', 'V-100793']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
