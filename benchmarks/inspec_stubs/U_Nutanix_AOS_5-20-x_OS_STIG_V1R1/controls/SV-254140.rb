control 'SV-254140' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for all account creations, modifications, disabling, and terminations.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as all account creations, modifications, disabling, and terminations.'
  desc 'check', 'Confirm Nutanix AOS auditing is configured to generate audit records for all account creations, modifications, disabling, and terminations.

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

$ sudo grep -w chage /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w newgrp /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57625r846506_chk'
  tag severity: 'medium'
  tag gid: 'V-254140'
  tag rid: 'SV-254140r846508_rule'
  tag stig_id: 'NUTX-OS-000330'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57576r846507_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
