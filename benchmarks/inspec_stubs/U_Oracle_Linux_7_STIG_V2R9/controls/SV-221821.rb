control 'SV-221821' do
  title 'The Oracle Linux operating system must audit all uses of the init_module and finit_module syscalls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify the operating system generates audit records upon successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls. 

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

$ sudo grep init_module /etc/audit/audit.rules 

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange

-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange

If there are no audit rules defined for "init_module" and "finit_module", this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records upon successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls. 

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

Note: The rules are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be configured. 

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange

-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23536r833098_chk'
  tag severity: 'medium'
  tag gid: 'V-221821'
  tag rid: 'SV-221821r833100_rule'
  tag stig_id: 'OL07-00-030820'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-23525r833099_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-99381', 'SV-108485']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
