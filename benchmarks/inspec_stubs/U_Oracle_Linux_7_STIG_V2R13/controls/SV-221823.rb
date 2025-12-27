control 'SV-221823' do
  title 'The Oracle Linux operating system must audit all uses of the delete_module syscall.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "delete_module" syscall occur. 

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

$ sudo grep -w "delete_module" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module-change

-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module-change

If there are no audit rules defined for "delete_module", this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "delete_module" syscall occur. 

Add or update the following rules in "/etc/audit/rules.d/audit.rules": 

Note: The rules are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be configured.

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module-change

-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module-change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23538r833101_chk'
  tag severity: 'medium'
  tag gid: 'V-221823'
  tag rid: 'SV-221823r833103_rule'
  tag stig_id: 'OL07-00-030830'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-23527r833102_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-99385', 'SV-108489']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
