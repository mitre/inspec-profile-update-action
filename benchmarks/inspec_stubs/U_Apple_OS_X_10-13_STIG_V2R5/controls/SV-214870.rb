control 'SV-214870' do
  title 'The macOS system must disable Siri pop-ups.'
  desc 'Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the Ubuntu operating system without identification or authentication.

'
  desc 'check', 'To check if the "SkipSiriSetup" prompt is enabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipSiriSetup

If the output is null or "SkipSiriSetup" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16070r397182_chk'
  tag severity: 'medium'
  tag gid: 'V-214870'
  tag rid: 'SV-214870r609363_rule'
  tag stig_id: 'AOSX-13-000556'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16068r397183_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81619', 'SV-96333']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
