control 'SV-217967' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications using fchownat.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc 'check', 'To determine if the system is configured to audit calls to the "fchownat" system call, run the following command:

$ sudo grep -w "fchownat" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit the "fchownat" system call, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 \\
-k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19448r376916_chk'
  tag severity: 'low'
  tag gid: 'V-217967'
  tag rid: 'SV-217967r603264_rule'
  tag stig_id: 'RHEL-06-000189'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-19446r376917_fix'
  tag 'documentable'
  tag legacy: ['V-38554', 'SV-50355']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
