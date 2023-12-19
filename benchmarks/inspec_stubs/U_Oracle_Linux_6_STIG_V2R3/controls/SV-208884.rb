control 'SV-208884' do
  title 'The audit system must be configured to audit all attempts to alter system time through stime.'
  desc 'Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.'
  desc 'check', 'If the system is 64-bit only, this is not applicable.

To determine if the system is configured to audit calls to the "stime" system call, run the following command:

$ sudo grep -w "stime" /etc/audit/audit.rules
-a always,exit -F arch=b32 -S stime -k audit_time_rules

If the system is not configured to audit the "stime" system call, this is a finding.'
  desc 'fix', 'On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S stime -k audit_time_rules

Note: On a 64-bit system, it is not necessary to define a rule for "stime".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9137r357632_chk'
  tag severity: 'low'
  tag gid: 'V-208884'
  tag rid: 'SV-208884r603263_rule'
  tag stig_id: 'OL6-00-000169'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-9137r357633_fix'
  tag 'documentable'
  tag legacy: ['V-51067', 'SV-65273']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
