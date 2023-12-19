control 'SV-100501' do
  title 'The SLES for vRealize audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration to determine if file and directory deletions are audited:

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "rmdir"

If no results are returned, or the results do not contain "-S rmdir", this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules" in order to capture file and directory deletion events:

-a always,exit -F arch=b64 -S rmdir -S rm
-a always,exit -F arch=b32 -S rmdir -S rm'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89851'
  tag rid: 'SV-100501r1_rule'
  tag stig_id: 'VRAU-SL-001465'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-96593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
