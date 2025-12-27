control 'SV-254137' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for system module management actions.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as: Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.'
  desc 'check', 'Confirm Nutanix AOS auditing is configured to generate audit records for all access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.

$ sudo grep -w "init_module" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S init_module -k audit_network_modifications_modules
-a always,exit -F arch=b32 -S init_module -k audit_network_modifications_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

$ sudo grep -w "finit_module" /etc/audit/audit.rules
-a always,exit -F arch=b32 -S finit_module -k module-change
-a always,exit -F arch=b64 -S finit_module -k module-change

$ sudo grep -w "delete_module" /etc/audit/audit.rules
-a always,exit -F arch=b64 -S delete_module -k audit_network_modifications_modules
-a always,exit -F arch=b32 -S delete_module -k audit_network_modifications_modules
-a always,exit -F arch=b64 -S delete_module -k modules
-a always,exit -F arch=b32 -S delete_module -k modules

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57622r846497_chk'
  tag severity: 'medium'
  tag gid: 'V-254137'
  tag rid: 'SV-254137r846499_rule'
  tag stig_id: 'NUTX-OS-000300'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57573r846498_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
