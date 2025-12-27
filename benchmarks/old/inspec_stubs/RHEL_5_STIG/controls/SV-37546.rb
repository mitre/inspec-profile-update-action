control 'SV-37546' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'fix', 'Edit /etc/security/limits.conf and set a hard limit for "core" to 0 for all users.  A new login will be required for the changes to take effect.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-11996'
  tag rid: 'SV-37546r2_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'GEN003500'
  tag fix_id: 'F-31460r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
