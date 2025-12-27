control 'SV-254156' do
  title 'Nutanix AOS must generate audit records for privileged security activities.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records for privileged activities or other system-level access.

$ sudo grep /etc/shadow /etc/audit/audit.rules
-w /etc/shadow -p wa -k audit_account_changes

$ sudo grep /etc/security/opasswd /etc/audit/audit.rules
-w /etc/security/opasswd -p wa -k audit_account_changes

$ sudo grep /etc/passwd /etc/audit/audit.rules
-w /etc/passwd -p wa -k audit_account_changes

$ sudo grep /etc/gshadow /etc/audit/audit.rules
-w /etc/gshadow -p wa -k audit_account_changes

$ sudo grep /etc/group /etc/audit/audit.rules
-w /etc/group -p wa -k audit_account_changes

$ sudo grep /etc/sudoers /etc/audit/audit.rules
-w /etc/sudoers -p wa -k actions

$ sudo grep /etc/sudoers.d/ /etc/audit/audit.rules
-w /etc/sudoers.d/ -p wa -k actions

$ sudo grep -w /usr/bin/su /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w sudo /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w gpasswd /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w passwd /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

If the privileged activities access listed do not return any output, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57641r846554_chk'
  tag severity: 'medium'
  tag gid: 'V-254156'
  tag rid: 'SV-254156r846556_rule'
  tag stig_id: 'NUTX-OS-000520'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-57592r846555_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
