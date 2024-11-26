control 'SV-208885' do
  title 'The audit system must be configured to audit all attempts to alter system time through clock_settime.'
  desc 'Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.'
  desc 'check', 'To determine if the system is configured to audit calls to the "clock_settime" system call, run the following command: 

$ sudo grep -w "clock_settime" /etc/audit/audit.rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit the "clock_settime" system call, this is a finding.'
  desc 'fix', 'On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

If the system is 64-bit, then also add the following: 

# audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9138r357635_chk'
  tag severity: 'low'
  tag gid: 'V-208885'
  tag rid: 'SV-208885r603263_rule'
  tag stig_id: 'OL6-00-000171'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-9138r357636_fix'
  tag 'documentable'
  tag legacy: ['SV-65275', 'V-51069']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
