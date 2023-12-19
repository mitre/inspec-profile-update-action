control 'SV-45207' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.
# ps -ef |grep auditd 
If the auditd process is not found, this is a finding.'
  desc 'fix', 'Start the auditd service and set it to start on boot.
# service auditd start ; chkconfig auditd on'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42555r1_chk'
  tag severity: 'medium'
  tag gid: 'V-811'
  tag rid: 'SV-45207r1_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'GEN002660'
  tag fix_id: 'F-38603r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
