control 'SV-254154' do
  title 'Nutanix AOS must audit attempts to modify or delete security objects.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Confirm Nutanix AOS generates audit records when successful/unsuccessful attempts to delete security objects occur.

$ sudo grep -iw rename /etc/audit/audit.rules
-a exit,never -F arch=b64 -S rename -F success=1 -F uid=1000 -F exit=0
-a exit,never -F arch=b64 -S rename -F success=0 -F uid=1000 -F exit=-2
-a always,exit -F arch=b64 -S rename -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rename -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -iw renameat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S renameat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S renameat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -iw rmdir /etc/audit/audit.rules
-a always,exit -F arch=b64 -S rmdir -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rmdir -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

grep -iw unlink /etc/audit/audit.rules
-a exit,never -F arch=b64 -S unlink -F success=1 -F uid=1000 -F exit=0
-a exit,never -F arch=b64 -S unlink -F success=0 -F uid=1000 -F exit=-2
-a always,exit -F arch=b64 -S unlink -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlink -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

grep -iw unlinkat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S unlinkat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlinkat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

If both the "b32" and "b64" audit rules are not defined for the syscalls listed, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57639r846548_chk'
  tag severity: 'medium'
  tag gid: 'V-254154'
  tag rid: 'SV-254154r846550_rule'
  tag stig_id: 'NUTX-OS-000480'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-57590r846549_fix'
  tag satisfies: ['SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
