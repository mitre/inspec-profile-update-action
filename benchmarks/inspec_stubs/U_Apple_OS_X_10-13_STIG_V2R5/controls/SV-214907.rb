control 'SV-214907' do
  title 'The macOS system must be configured with iTunes Music Sharing disabled.'
  desc "When iTunes Music Sharing is enabled, the computer starts a network listening service that shares the contents of the user's music collection with other users in the same subnet. Unnecessary network services should always be disabled because they increase the attack surface of the system. Disabling iTunes Music Sharing mitigates this risk."
  desc 'check', 'To check if iTunes Music Sharing is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep disableSharedMusic

If the return is null or does not contain “disableSharedMusic = 1” this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16107r397293_chk'
  tag severity: 'low'
  tag gid: 'V-214907'
  tag rid: 'SV-214907r609363_rule'
  tag stig_id: 'AOSX-13-001140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16105r397294_fix'
  tag 'documentable'
  tag legacy: ['V-81693', 'SV-96407']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
