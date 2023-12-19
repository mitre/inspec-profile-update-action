control 'SV-215413' do
  title 'AIX must contain no .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', 'Search for any ".forward" files on the system using command: 
# find / -name .forward -print 

If any ".forward" files are found on the system, this is a finding.'
  desc 'fix', 'Run the following command to remove all ".forward" files on the system:
# find / -name .forward -exec rm -rf {} \\;'
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16611r294690_chk'
  tag severity: 'low'
  tag gid: 'V-215413'
  tag rid: 'SV-215413r508663_rule'
  tag stig_id: 'AIX7-00-003115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16609r294691_fix'
  tag 'documentable'
  tag legacy: ['SV-101753', 'V-91655']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
