control 'SV-218376' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.
# ps -ef |grep auditd 
If the auditd process is not found, this is a finding.'
  desc 'fix', 'Start the auditd service and set it to start on boot.
# service auditd start ; chkconfig auditd on'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19851r554465_chk'
  tag severity: 'medium'
  tag gid: 'V-218376'
  tag rid: 'SV-218376r603259_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-19849r554466_fix'
  tag 'documentable'
  tag legacy: ['V-811', 'SV-63819']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
