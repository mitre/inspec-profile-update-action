control 'SV-257148' do
  title 'The macOS system must be configured to disable hot corners.'
  desc 'Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.'
  desc 'check', 'Verify the macOS system is configured to disable hot corners with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "wvous"

"wvous-bl-corner" = 0;
"wvous-br-corner" = 0;
"wvous-tl-corner" = 0;
"wvous-tr-corner" = 0;

If the command does not return the following, this is a finding.

"wvous-bl-corner = 0;
wvous-br-corner = 0;
wvous-tl-corner = 0;
wvous-tr-corner = 0;"'
  desc 'fix', 'Configure the macOS system to disable hot corners by installing the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60833r905075_chk'
  tag severity: 'medium'
  tag gid: 'V-257148'
  tag rid: 'SV-257148r905077_rule'
  tag stig_id: 'APPL-13-000007'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-60774r905076_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
