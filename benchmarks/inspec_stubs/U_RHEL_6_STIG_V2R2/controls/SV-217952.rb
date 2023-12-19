control 'SV-217952' do
  title 'The audit system must be configured to audit all attempts to alter system time through settimeofday.'
  desc 'Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.'
  desc 'check', 'To determine if the system is configured to audit calls to the "settimeofday" system call, run the following command:

$ sudo grep -w "settimeofday" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to the "settimeofday" syscall, this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules

If the system is 64-bit, then also add the following: 

# audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19433r376871_chk'
  tag severity: 'low'
  tag gid: 'V-217952'
  tag rid: 'SV-217952r603264_rule'
  tag stig_id: 'RHEL-06-000167'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-19431r376872_fix'
  tag 'documentable'
  tag legacy: ['V-38522', 'SV-50323']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
