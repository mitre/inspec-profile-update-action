control 'SV-252442' do
  title 'The macOS system must be configured to disable hot corners.'
  desc 'Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.'
  desc 'check', 'To check if the system is configured to disable hot corners, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous

If the return is null, or does not equal:
"wvous-bl-corner = 0
wvous-br-corner = 0;
wvous-tl-corner = 0;
wvous-tr-corner = 0;" 
this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55898r816138_chk'
  tag severity: 'medium'
  tag gid: 'V-252442'
  tag rid: 'SV-252442r816140_rule'
  tag stig_id: 'APPL-12-000007'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-55848r816139_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
