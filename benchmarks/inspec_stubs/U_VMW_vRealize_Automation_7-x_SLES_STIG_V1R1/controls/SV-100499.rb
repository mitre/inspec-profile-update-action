control 'SV-100499' do
  title 'The SLES for vRealize audit system must be configured to audit user deletions of files and programs.'
  desc 'Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.'
  desc 'check', 'To determine if the system is configured to audit calls to the "unlink" system call, run the following command: 

# auditctl -l | grep syscall | grep unlink | grep -v unlinkat

If the system is configured to audit this activity, it will return several lines.

If it does not, this is a finding.

To determine if the system is configured to audit calls to the "unlinkat" system call, run the following command: 

# auditctl -l | grep syscall | grep unlinkat

If the system is configured to audit this activity, it will return several lines.

If it does not, this is a finding.

To determine if the system is configured to audit calls to the "rename" system call, run the following command: 

# auditctl -l | grep syscall | grep rename | grep -v renameat

If the system is configured to audit this activity, it will return several lines.

If it does not, this is a finding.

To determine if the system is configured to audit calls to the "renameat" system call, run the following command: 

# auditctl -l | grep syscall | grep renameat

If the system is configured to audit this activity, it will return several lines.

If it does not, this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of deletions of files and programs:

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid=0
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89541r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89849'
  tag rid: 'SV-100499r1_rule'
  tag stig_id: 'VRAU-SL-001460'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-96591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
