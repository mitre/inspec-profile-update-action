control 'SV-208893' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications using chmod, fchmod, and fchmodat.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary, since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', 'To determine if the system is configured to audit calls to the "chmod", "fchmod", and "fchmodat" system calls, run the following command:

$ sudo grep chmod /etc/audit/audit.rules

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid=0 -k perm_mod

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit the "chmod", "fchmod", and "fchmodat" system calls, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid=0 -k perm_mod'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9146r810466_chk'
  tag severity: 'low'
  tag gid: 'V-208893'
  tag rid: 'SV-208893r810467_rule'
  tag stig_id: 'OL6-00-000184'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-9146r809112_fix'
  tag 'documentable'
  tag legacy: ['SV-65379', 'V-51169']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
