control 'SV-257272' do
  title 'CylancePROTECT Mobile must be configured to disable anonymous data collection by BlackBerry for both iOS and Android devices.'
  desc 'The required application configurations will ensure that the minimum security baseline of the system is maintained to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify anonymous data collection by BlackBerry for both iOS and Android devices has been disabled by CylancePROTECT Mobile:

1. Log on to the BlackBerry UEM console.
2. In Policies and profiles >> Protection >> BlackBerry Protect, select a BlackBerry Protect profile.
3. On the iOS tab, in the "Statistics collection" section, verify "Allow collection of anonymized statistics from devices to improve the performance of BlackBerry Protect" check box has not been selected.
4. On the Android tab, in the "Statistics collection" section, verify the "Allow collection of anonymized statistics from devices to improve the performance of BlackBerry Protect" check box has not been selected.

If CylancePROTECT Mobile has not disabled anonymous data collection by BlackBerry for both iOS and Android devices, this is a finding.'
  desc 'fix', 'Disable CylancePROTECT Mobile anonymous data collection by BlackBerry for both iOS and Android devices:

1. Log on to the BlackBerry UEM console.
2. In Policies and profiles >> Protection >> BlackBerry Protect, select and edit a BlackBerry Protect profile.
3. On the iOS tab, in the "Statistics collection" section, clear the "Allow collection of anonymized statistics from devices to improve the performance of BlackBerry Protect" check box.
4. On the Android tab, in the "Statistics collection" section, clear the "Allow collection of anonymized statistics from devices to improve the performance of BlackBerry Protect" check box.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60956r918398_chk'
  tag severity: 'medium'
  tag gid: 'V-257272'
  tag rid: 'SV-257272r918400_rule'
  tag stig_id: 'BBCP-00-013800'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60898r918399_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
