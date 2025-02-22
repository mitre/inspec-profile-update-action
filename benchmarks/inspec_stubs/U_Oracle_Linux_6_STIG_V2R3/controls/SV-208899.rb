control 'SV-208899' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc 'check', 'To determine if the system is configured to audit calls to the "fremovexattr" system call, run the following command: 

$ sudo grep -w "fremovexattr" /etc/audit/audit.rules
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit the "fremovexattr" system call, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9152r357677_chk'
  tag severity: 'low'
  tag gid: 'V-208899'
  tag rid: 'SV-208899r603263_rule'
  tag stig_id: 'OL6-00-000190'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-9152r357678_fix'
  tag 'documentable'
  tag legacy: ['V-51157', 'SV-65367']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
