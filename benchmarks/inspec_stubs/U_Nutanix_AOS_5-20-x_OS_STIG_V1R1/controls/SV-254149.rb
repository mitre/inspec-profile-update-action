control 'SV-254149' do
  title 'Nutanix AOS must generate audit records for file extended attribute actions.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records on all successful/unsuccessful attempts to access categories of information occur.

$ sudo grep -w setxattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S setxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fsetxattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fsetxattr-F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w lsetxattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S lsetxattr-F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w removexattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S removexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fremovexattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w lremovexattr /etc/audit/audit.rules
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

If the output does not contain all of the above rules, this is a finding.
If both the "b32" and "b64" audit rules are not defined for the listed syscall(s), this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57634r846533_chk'
  tag severity: 'medium'
  tag gid: 'V-254149'
  tag rid: 'SV-254149r846535_rule'
  tag stig_id: 'NUTX-OS-000430'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag fix_id: 'F-57585r846534_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
