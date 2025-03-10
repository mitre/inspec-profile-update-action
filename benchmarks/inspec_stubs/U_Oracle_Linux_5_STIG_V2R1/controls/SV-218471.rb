control 'SV-218471' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'check', '# ulimit -Hc
If the above command does not return 0 and the enabling of core dumps has not been documented and approved by the ISSO, this a finding.'
  desc 'fix', 'Edit /etc/security/limits.conf and set a hard limit for "core" to 0 for all users. A new logon will be required for the changes to take effect.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19946r562567_chk'
  tag severity: 'low'
  tag gid: 'V-218471'
  tag rid: 'SV-218471r603259_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19944r562568_fix'
  tag 'documentable'
  tag legacy: ['V-11996', 'SV-64311']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
