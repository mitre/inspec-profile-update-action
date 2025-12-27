control 'SV-254151' do
  title 'Nutanix AOS must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records when successful/unsuccessful attempts to modify privileged objects occur.

$ sudo grep /etc/sudoers /etc/audit/audit.rules
-w /etc/sudoers -p wa -k actions

$ sudo grep /etc/sudoers.d/ /etc/audit/audit.rules
-w /etc/sudoers.d/ -p wa -k actions

$ sudo grep -w /usr/bin/su /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w sudo /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w newgrp /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -i /usr/bin/chsh /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

If the privileged activities access listed do not return any output, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57636r846539_chk'
  tag severity: 'medium'
  tag gid: 'V-254151'
  tag rid: 'SV-254151r846541_rule'
  tag stig_id: 'NUTX-OS-000450'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-57587r846540_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
