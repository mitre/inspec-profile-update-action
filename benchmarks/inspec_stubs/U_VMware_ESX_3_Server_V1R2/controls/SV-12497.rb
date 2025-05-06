control 'SV-12497' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in denial-of-Service.  Process core dumps can be useful for software debugging.'
  desc 'check', 'Determine if process core dumps are enabled on the system.  If process core dumps are enabled, this is a finding.'
  desc 'fix', 'Disable process core dumps on the system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7961r2_chk'
  tag severity: 'low'
  tag gid: 'V-11996'
  tag rid: 'SV-12497r2_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'GEN003500'
  tag fix_id: 'F-11257r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
