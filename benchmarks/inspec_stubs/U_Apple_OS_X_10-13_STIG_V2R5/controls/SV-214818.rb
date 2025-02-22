control 'SV-214818' do
  title 'The macOS system must be configured with automatic actions disabled for picture CDs.'
  desc 'Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for picture CDs mitigates this risk.'
  desc 'check', %q(If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To check if the system has the correct setting for picture CDs in the configuration profile, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.picture.appeared'

If this is not defined or "action" is not set to "1", this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16018r397026_chk'
  tag severity: 'medium'
  tag gid: 'V-214818'
  tag rid: 'SV-214818r609363_rule'
  tag stig_id: 'AOSX-13-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16016r397027_fix'
  tag 'documentable'
  tag legacy: ['V-81497', 'SV-96211']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
