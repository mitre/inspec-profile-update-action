control 'SV-217965' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications using fchmodat.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc 'check', 'To determine if the system is configured to audit calls to the "fchmodat" system call, run the following command:

$ sudo grep -w "fchmodat" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit the "fchmodat" system call, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19446r376910_chk'
  tag severity: 'low'
  tag gid: 'V-217965'
  tag rid: 'SV-217965r603264_rule'
  tag stig_id: 'RHEL-06-000187'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-19444r376911_fix'
  tag 'documentable'
  tag legacy: ['V-38550', 'SV-50351']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
