control 'SV-217975' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.'
  desc 'check', 'To verify that the audit system collects unauthorized file accesses, run the following commands: 

# grep EACCES /etc/audit/audit.rules

-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid=0 -k access

# grep EPERM /etc/audit/audit.rules

-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid=0 -k access   
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid=0 -k access

If the system is 64-bit and does not return rules for both "b32" and "b64" architectures, this is a finding.

If either command lacks output, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules":

-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid=0 -k access   

If the system is 64-bit, then also add the following:

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid=0 -k access'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19456r376940_chk'
  tag severity: 'low'
  tag gid: 'V-217975'
  tag rid: 'SV-217975r603264_rule'
  tag stig_id: 'RHEL-06-000197'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-19454r376941_fix'
  tag 'documentable'
  tag legacy: ['V-38566', 'SV-50367']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
