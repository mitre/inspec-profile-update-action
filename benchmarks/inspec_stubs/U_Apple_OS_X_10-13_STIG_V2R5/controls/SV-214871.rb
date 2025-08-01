control 'SV-214871' do
  title 'The macOS system must disable iCloud Back to My Mac feature.'
  desc 'The Back to My Mac is an iCloud feature permitting users to connect to a Mac, AirPort Disk, or Time Capsule using another Mac or another Internet connected device. When connected users can transfer data and see a live version of the screen content.

'
  desc 'check', 'To view the setting for the Back to My Mac configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudBTMM

If the output is null or not "allowCloudBTMM = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16071r397185_chk'
  tag severity: 'medium'
  tag gid: 'V-214871'
  tag rid: 'SV-214871r609363_rule'
  tag stig_id: 'AOSX-13-000557'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16069r397186_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81621', 'SV-96335']
  tag cci: ['CCI-001774', 'CCI-000381']
  tag nist: ['CM-7 (5) (b)', 'CM-7 a']
end
