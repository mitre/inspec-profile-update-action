control 'SV-38946' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.
# /usr/sbin/audit query | head -1
If the response Auditing On is not returned, this is a finding.'
  desc 'fix', 'Use SMIT or command line to enable auditing on the system.  
#audit start

Additionally,  make sure auditing subsystem starts on system startup.
#mkitab -i cron "audit:2:once:/usr/sbin/audit start 2>&1 > 
/dev/console"'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28347r1_chk'
  tag severity: 'medium'
  tag gid: 'V-811'
  tag rid: 'SV-38946r1_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'GEN002660'
  tag fix_id: 'F-32465r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
