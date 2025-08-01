control 'SV-253050' do
  title 'Successful/unsuccessful uses of the "kmod" command in TOSS must generate an audit record.'
  desc '"Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The "kmod" command is used to control Linux Kernel modules.

'
  desc 'check', 'Verify that TOSS is configured to audit the execution of the module management program "kmod", by running the following command:

$ sudo grep "/usr/bin/kmod" /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to audit the execution of the module management program "kmod" by adding or updating the following line to "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56503r824820_chk'
  tag severity: 'medium'
  tag gid: 'V-253050'
  tag rid: 'SV-253050r824822_rule'
  tag stig_id: 'TOSS-04-031240'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-56453r824821_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
