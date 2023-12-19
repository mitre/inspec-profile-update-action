control 'SV-45679' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'check', '# ulimit -c
If the above command does not return 0 and the enabling of core dumps has not been documented and approved by the IAO, this a finding.'
  desc 'fix', 'Edit /etc/security/limits.conf and set a hard limit for "core" to 0 for all users.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43045r1_chk'
  tag severity: 'low'
  tag gid: 'V-11996'
  tag rid: 'SV-45679r1_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'GEN003500'
  tag fix_id: 'F-39077r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
