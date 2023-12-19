control 'SV-214819' do
  title 'The macOS system must be configured with automatic actions disabled for video DVDs.'
  desc 'Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for video DVDs mitigates this risk.'
  desc 'check', %q(If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To check if the system has the correct setting for video DVDs in the configuration profile, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.dvd.video.appeared'

If this is not defined or "action" is not set to "1", this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16019r397029_chk'
  tag severity: 'medium'
  tag gid: 'V-214819'
  tag rid: 'SV-214819r609363_rule'
  tag stig_id: 'AOSX-13-000105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16017r397030_fix'
  tag 'documentable'
  tag legacy: ['SV-96213', 'V-81499']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
