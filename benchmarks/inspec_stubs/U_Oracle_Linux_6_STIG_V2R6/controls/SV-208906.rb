control 'SV-208906' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary, since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', 'To verify that the audit system collects unauthorized file accesses, run the following commands: 

# grep EACCES /etc/audit/audit.rules

-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid=0 -k access

# grep EPERM /etc/audit/audit.rules

-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid=0 -k access   
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid=0 -k access

If the system is 64-bit and does not return rules for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit "EACCES" and "EPERM" of the "creat", "open", "openat", "truncate", "ftruncate", and "open_by_handle_at" system calls, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid=0 -k access   

If the system is 64-bit, then also add the following:
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,open_by_handle_at -F exit=-EPERM -F auid=0 -k access'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9159r809120_chk'
  tag severity: 'low'
  tag gid: 'V-208906'
  tag rid: 'SV-208906r810471_rule'
  tag stig_id: 'OL6-00-000197'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-9159r809121_fix'
  tag 'documentable'
  tag legacy: ['V-51143', 'SV-65353']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
