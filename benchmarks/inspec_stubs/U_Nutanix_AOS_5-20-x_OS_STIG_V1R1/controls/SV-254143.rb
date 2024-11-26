control 'SV-254143' do
  title 'Nutanix AOS must produce audit records containing the full-text recording of successful and unsuccessful uses and variations of the creat privileged commands.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records on all successful/unsuccessful attempts to access privileges occur.

$ sudo grep -iw creat /etc/audit/audit.rules
 -a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid=0 -k access.
 -a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid=0 -k access.
 -a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access.
 -a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access.
 -a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid=0 -k access.
 -a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid=0 -k access.
 -a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access.
 -a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access.

If the output does not contain all of the above rules, this is a finding.
If both the "b32" and "b64" audit rules are not defined for the listed syscall(s), this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57628r858400_chk'
  tag severity: 'medium'
  tag gid: 'V-254143'
  tag rid: 'SV-254143r858400_rule'
  tag stig_id: 'NUTX-OS-000370'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-57579r846516_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
