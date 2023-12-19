control 'SV-27402' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'check', '# lsuser -a core ALL

If any user does not have a value of core = 0, this is a finding.'
  desc 'fix', '# chsec -f /etc/security/limits -s default -a core=0'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28566r1_chk'
  tag severity: 'low'
  tag gid: 'V-11996'
  tag rid: 'SV-27402r1_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'GEN003500'
  tag fix_id: 'F-24650r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
