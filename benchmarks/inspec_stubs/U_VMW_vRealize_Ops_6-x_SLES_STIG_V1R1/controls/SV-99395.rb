control 'SV-99395' do
  title 'The SLES for vRealize audit system must be configured to audit file deletions.'
  desc 'If the SLES for vRealize system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check SLES for vRealize audit configuration to determine if file and directory deletions are audited:

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "rmdir"

If no results are returned or the results do not contain "-S rmdir", this is a finding.'
  desc 'fix', 'Add the following to the "/etc/audit/audit.rules" file in order to capture file and directory deletion events:

-a always,exit -F arch=b64 -S rmdir -S rm
-a always,exit -F arch=b32 -S rmdir -S rm'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88437r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88745'
  tag rid: 'SV-99395r1_rule'
  tag stig_id: 'VROM-SL-001440'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-95487r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
