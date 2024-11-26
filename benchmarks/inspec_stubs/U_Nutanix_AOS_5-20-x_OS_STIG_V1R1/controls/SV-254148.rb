control 'SV-254148' do
  title 'Nutanix AOS must generate audit records for file permission actions.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records on all successful/unsuccessful attempts to access categories of information occur.

$ sudo grep -w chmod /etc/audit/audit.rules
-a always,exit -F arch=b64 -S chmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchmod /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchmodat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

If the output does not contain all of the above rules, this is a finding.
If both the "b32" and "b64" audit rules are not defined for the listed syscall(s), this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57633r846530_chk'
  tag severity: 'medium'
  tag gid: 'V-254148'
  tag rid: 'SV-254148r846532_rule'
  tag stig_id: 'NUTX-OS-000420'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag fix_id: 'F-57584r846531_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
