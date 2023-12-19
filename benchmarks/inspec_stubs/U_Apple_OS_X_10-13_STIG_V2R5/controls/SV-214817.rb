control 'SV-214817' do
  title 'The macOS system must be configured with automatic actions disabled for music CDs.'
  desc 'Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for music CDs mitigates this risk.'
  desc 'check', %q(If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To check if the system has the correct setting for music CDs in the configuration profile, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.music.appeared'

If this is not defined or "action" is not set to "1", this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16017r397023_chk'
  tag severity: 'medium'
  tag gid: 'V-214817'
  tag rid: 'SV-214817r609363_rule'
  tag stig_id: 'AOSX-13-000095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16015r397024_fix'
  tag 'documentable'
  tag legacy: ['V-81493', 'SV-96207']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
