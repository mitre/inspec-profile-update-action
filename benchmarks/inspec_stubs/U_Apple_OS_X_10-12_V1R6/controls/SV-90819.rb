control 'SV-90819' do
  title 'The OS X system must be configured with iTunes Music Sharing disabled.'
  desc "When iTunes Music Sharing is enabled, the computer starts a network listening service that shares the contents of the user's music collection with other users in the same subnet. Unnecessary network services should always be disabled because they increase the attack surface of the system. Disabling iTunes Music Sharing mitigates this risk."
  desc 'check', 'To check if iTunes Music Sharing is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep disableSharedMusic

If "disableSharedMusic" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75817r1_chk'
  tag severity: 'low'
  tag gid: 'V-76131'
  tag rid: 'SV-90819r1_rule'
  tag stig_id: 'AOSX-12-001140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
