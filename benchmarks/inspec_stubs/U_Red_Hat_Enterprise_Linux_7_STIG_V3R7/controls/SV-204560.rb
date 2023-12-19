control 'SV-204560' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the init_module and finit_module syscalls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify the operating system generates audit records upon successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls. 

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

# grep init_module /etc/audit/audit.rules 

-a always,exit -F arch=b32 -S init_module,finit_module -k modulechange

-a always,exit -F arch=b64 -S init_module,finit_module -k modulechange

If both the "b32" and "b64" audit rules are not defined for the "init_module" and "finit_module" syscalls, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records upon successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls. 

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S init_module,finit_module -k modulechange

-a always,exit -F arch=b64 -S init_module,finit_module -k modulechange

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4684r809816_chk'
  tag severity: 'medium'
  tag gid: 'V-204560'
  tag rid: 'SV-204560r809822_rule'
  tag stig_id: 'RHEL-07-030820'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-4684r809821_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-72187', 'SV-86811']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
