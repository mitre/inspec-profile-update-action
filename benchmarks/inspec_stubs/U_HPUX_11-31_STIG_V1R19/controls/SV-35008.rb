control 'SV-35008' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'check', '# grep -c ulimit /etc/profile

If the return value of this command is 0, this is a finding.

If the return value of this command is not 0:
# grep ulimit /etc/profile

If the -c argument with a value of 0 is not present, this is a finding.'
  desc 'fix', 'Edit /etc/profile, ensure the ulimit command is present with the -c argument of the ulimit command set to 0.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36487r1_chk'
  tag severity: 'low'
  tag gid: 'V-11996'
  tag rid: 'SV-35008r1_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'GEN003500'
  tag fix_id: 'F-31839r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
