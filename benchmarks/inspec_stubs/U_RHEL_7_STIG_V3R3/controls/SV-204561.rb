control 'SV-204561' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the finit_module syscall.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "finit_module" syscall occur. 

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

# grep -iw finit_module /etc/audit/audit.rules

-a always,exit -F arch=b32 -S finit_module -k module-change

-a always,exit -F arch=b64 -S finit_module -k module-change

If both the "b32" and "b64" audit rules are not defined for the "finit_module" syscall, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "finit_module" syscall occur. 

Add or update the following rules in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F arch=b32 -S finit_module -k module-change

-a always,exit -F arch=b64 -S finit_module -k module-change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4685r88875_chk'
  tag severity: 'medium'
  tag gid: 'V-204561'
  tag rid: 'SV-204561r603261_rule'
  tag stig_id: 'RHEL-07-030821'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-4685r88876_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-79001', 'SV-93707']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
