control 'SV-254138' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for directory and permissions management actions.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as: Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.'
  desc 'check', 'Confirm Nutanix AOS auditing is configured to generate audit records for all access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.

$ sudo grep -w "\\-S mount" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S mount -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S mount -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w "rename" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S rename -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rename -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w "renameat" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S renameat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S renameat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w "rmdir" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S rmdir -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rmdir -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w "unlink" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S unlink -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlink -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w "unlinkat" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S unlinkat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlinkat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w chown /etc/audit/audit.rules
-a always,exit -F arch=b64 -S chown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w chmod /etc/audit/audit.rules
-a always,exit -F arch=b64 -S chmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w lchown /etc/audit/audit.rules
-a always,exit -F arch=b64 -S lchown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lchown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchownat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchownat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchownat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchown /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchown -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchmodat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

$ sudo grep -w fchmod /etc/audit/audit.rules
-a always,exit -F arch=b64 -S fchmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmod -F auid=0 -k audit_time_perm_mod_export_delete
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k audit_time_perm_mod_export_delete

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57623r846500_chk'
  tag severity: 'medium'
  tag gid: 'V-254138'
  tag rid: 'SV-254138r846502_rule'
  tag stig_id: 'NUTX-OS-000310'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57574r846501_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
