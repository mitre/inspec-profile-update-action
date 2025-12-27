control 'SV-254139' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for file management actions.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as: Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.'
  desc 'check', 'Confirm Nutanix AOS auditing is configured to generate audit records for all access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.

$ sudo grep -iw truncate /etc/audit/audit.rules
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S truncate -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S truncate -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

$ sudo grep -iw openat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S openat-F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S openat -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S openat -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

$ sudo grep -iw open /etc/audit/audit.rules
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S open-F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S open -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S open -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

$ sudo grep -iw open_by_handle_at /etc/audit/audit.rules
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S open_by_handle_at-F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

$ sudo grep -iw ftruncate /etc/audit/audit.rules
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S ftruncate -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S ftruncate -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

$ sudo grep -iw creat /etc/audit/audit.rules
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b64 -S creat -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid=0 -k access
-a always,exit -F arch=b32 -S creat -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57624r846503_chk'
  tag severity: 'medium'
  tag gid: 'V-254139'
  tag rid: 'SV-254139r846505_rule'
  tag stig_id: 'NUTX-OS-000320'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57575r846504_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
