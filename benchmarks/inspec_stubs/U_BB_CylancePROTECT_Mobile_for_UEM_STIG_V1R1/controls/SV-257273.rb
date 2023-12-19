control 'SV-257273' do
  title 'CylancePROTECT Mobile must be configured to enable SMS text message scanning (iOS only).'
  desc 'The required application configurations will ensure that the minimum security baseline of the system is maintained to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify SMS text message scanning has been configured as required (iOS only):

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Protection >> BlackBerry Protect.
3. Open the BlackBerry Protect profile (have the site system administrator identify the profile from the list).
4. Select the iOS platform.
5. Verify that the "Enable message scanning" check box is selected.
6. Verify in the Scanning option drop-down list, one of the following has been selected AND "No scanning" is not selected:
-"Cloud scanning".
-"On device scanning".

If SMS text message scanning for iOS devices is not configured as required, this is a finding.'
  desc 'fix', 'Configure SMS text message scanning (iOS only).

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Protection >> BlackBerry Protect.
3. Open the BlackBerry Protect profile or create a new profile.
4. Select the iOS platform.
5. Verify that the "Enable message scanning" check box is selected.
6. In the Scanning option drop-down list, choose one of the following only (do not choose "No scanning"): "Cloud scanning" or "On device scanning".
7. Click "Save".
8. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60957r918401_chk'
  tag severity: 'medium'
  tag gid: 'V-257273'
  tag rid: 'SV-257273r918403_rule'
  tag stig_id: 'BBCP-00-013900'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60899r918402_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
