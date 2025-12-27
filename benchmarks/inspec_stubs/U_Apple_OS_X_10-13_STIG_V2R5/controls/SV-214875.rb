control 'SV-214875' do
  title 'The macOS system must disable iCloud Photo Library.'
  desc 'To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

'
  desc 'check', 'To check if the system has the correct setting in the configuration profile to disable access to the iCloud preference pane, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 DisabledPreferencePanes | grep icloud

If the return is not “com.apple.preferences.icloud”, this is a CAT I finding.

To view the setting for the iCloud Photo Library configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudPhotoLibrary

If the output is null or not "allowCloudPhotoLibrary = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16075r569443_chk'
  tag severity: 'medium'
  tag gid: 'V-214875'
  tag rid: 'SV-214875r609363_rule'
  tag stig_id: 'AOSX-13-000561'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16073r569444_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81629', 'SV-96343']
  tag cci: ['CCI-001774', 'CCI-000381']
  tag nist: ['CM-7 (5) (b)', 'CM-7 a']
end
