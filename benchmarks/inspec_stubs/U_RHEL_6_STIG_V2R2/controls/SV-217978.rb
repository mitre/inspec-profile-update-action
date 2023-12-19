control 'SV-217978' do
  title 'The audit system must be configured to audit user deletions of files and programs.'
  desc 'Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.'
  desc 'check', %q(To determine if the system is configured to audit user deletions of files and programs, run the following command:

$ sudo egrep -w 'rmdir|unlink|unlinkat|rename|renameat' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete

-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete

If the system is 64-bit and does not return rules for both "b32" and "b64" architectures, this is a finding.

If the system is not configured to audit "rmdir", this is a finding.

If the system is not configured to audit "unlink", this is a finding.

If the system is not configured to audit "unlinkat", this is a finding.

If the system is not configured to audit "rename", this is a finding.

If the system is not configured to audit "renameat", this is a finding.

If no line is returned, this is a finding.)
  desc 'fix', 'At a minimum, the audit system should collect file deletion events for all users and root. Add the following to "/etc/audit/audit.rules":

-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete

If the system is 64-bit, then also add the following:

-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19459r376949_chk'
  tag severity: 'low'
  tag gid: 'V-217978'
  tag rid: 'SV-217978r603264_rule'
  tag stig_id: 'RHEL-06-000200'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-19457r376950_fix'
  tag 'documentable'
  tag legacy: ['V-38575', 'SV-50376']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
