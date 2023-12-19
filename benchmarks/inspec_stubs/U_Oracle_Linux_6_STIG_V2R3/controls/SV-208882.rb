control 'SV-208882' do
  title 'The audit system must be configured to audit all attempts to alter system time through adjtimex.'
  desc 'Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.'
  desc 'check', 'To determine if the system is configured to audit calls to the "adjtimex" system call, run the following command: 

$ sudo grep -w "adjtimex" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

If the system is 64-bit and does not return a rule for both "b32" and "b64" architectures, this is a finding.
If the system is not configured to audit the "adjtimex" system call, this is a finding.'
  desc 'fix', 'On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules

If the system is 64-bit, then also add the following:

# audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9135r357626_chk'
  tag severity: 'low'
  tag gid: 'V-208882'
  tag rid: 'SV-208882r603263_rule'
  tag stig_id: 'OL6-00-000165'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-9135r357627_fix'
  tag 'documentable'
  tag legacy: ['V-51061', 'SV-65267']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
