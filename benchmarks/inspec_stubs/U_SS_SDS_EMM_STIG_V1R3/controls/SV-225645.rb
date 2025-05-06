control 'SV-225645' do
  title 'The Samsung SDS EMM must be configured with a periodicity for reachable events of six hours or less for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of installed mobile applications;
- read audit logs kept by the MD.'
  desc 'Key security-related status attributes must be queried frequently so the Samsung SDS EMM can report status of devices under management to the administrator and management. The frequency of these queries must be configured to an acceptable timeframe. Six hours or less is considered acceptable for normal operations.

SFR ID: FMT_SMF.1.1(2) c.3'
  desc 'check', 'Review the MDM agent configuration settings to determine if the agent is configured with a periodicity of reachable events set to six hours or less.

This validation procedure is performed on the Samsung SDS EMM Server Admin Console. 
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration.
3. For Android: On row 27 verify "Inventory Collection Period for Android (hr)" is set to "6" or less.
4. For iOS: On row 28 verify "Inventory Collection Period for iOS (hr)" is set to "6" or less.

If the periodicity of reachable events is not set to "6" hours or less, this is a finding.'
  desc 'fix', 'Configure the MDM agent periodicity of reachable events to six hours or less.

On the MDM console, do the following:
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Settings >> Server >> Configuration.
3. For Android: Ensure that row 27 "Inventory Collection Period for Android (hr)" shows a value of "6" or less.
4. For iOS: Ensure that row 28 "Inventory Collection Period for iOS (hr)" shows a value of "6" or less.
5. Click on the check-mark box in the top left of the "Configuration" screen to "Apply Changes".
6. Click "OK" on the "Notify" save completed window.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27346r560959_chk'
  tag severity: 'medium'
  tag gid: 'V-225645'
  tag rid: 'SV-225645r588007_rule'
  tag stig_id: 'SSDS-00-000550'
  tag gtitle: 'PP-MDM-411057'
  tag fix_id: 'F-27334r560960_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
