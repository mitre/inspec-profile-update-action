control 'SV-225124' do
  title 'The macOS system must be configured to disable hot corners.'
  desc 'Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.'
  desc 'check', 'To check if the system is configured to disable hot corners, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous

If the return is null or does not equal the following, this is a finding:

"wvous-bl-corner = 0
wvous-br-corner = 0;
wvous-tl-corner = 0;
wvous-tr-corner = 0;"'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26823r467540_chk'
  tag severity: 'medium'
  tag gid: 'V-225124'
  tag rid: 'SV-225124r610901_rule'
  tag stig_id: 'AOSX-15-000007'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-26811r467541_fix'
  tag 'documentable'
  tag legacy: ['V-102663', 'SV-111625']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
