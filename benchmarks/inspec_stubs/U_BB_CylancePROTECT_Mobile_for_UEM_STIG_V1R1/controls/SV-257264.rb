control 'SV-257264' do
  title 'CylancePROTECT Mobile must be configured with the following safe browsing controls for BlackBerry Dynamics apps:
-Block all unsafe URLs
-Select one of the following for "scanning option": "Cloud scanning" or "On device scanning".
-Disable "Allow users to override blocked resources and enable access to the requested domain".'
  desc 'The required application configurations will ensure that the minimum security baseline of the system is maintained to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify safe browsing with BlackBerry Dynamics apps has been configured as required:

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Protection >> BlackBerry Protect.
3. Open the BlackBerry Protect profile (have the site system administrator identify the profile from the list).
4. Select the platform (iOS or Android) to review.
5. Verify that the "Check for unsafe web resources within the BlackBerry Dynamics apps" check box is selected.
6. Verify "Block" is selected in the Action for unsafe web resources drop-down list.
7. Verify in the Scanning option drop-down list, one of the following has been selected AND "No scanning" is not selected:
-"Cloud scanning".
-"On device scanning".
8. Verify "Allow users to override blocked resources and enable access to the requested domain" is not selected.
9. Repeat steps 4–8 for the other platform (iOS or Android).

If safe browsing for BlackBerry Dynamics apps on iOS and Android devices is not configured as required, this is a finding.'
  desc 'fix', 'Configure the following safe browsing controls for BlackBerry Dynamics apps:
-Block all unsafe URLs.
-Select one of the following for "scanning option": Cloud scanning, on device scanning.
-Disable "Allow users to override blocked resources and enable access to the requested domain".

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Protection >> BlackBerry Protect.
3. Open the BlackBerry Protect profile or create a new profile.
4. Select the platform (iOS or Android) to configure safe browsing.
5. Verify that the "Check for unsafe web resources within the BlackBerry Dynamics apps" check box is selected.
6. In the Action for unsafe web resources drop-down list, select "Block".
7. In the Scanning option drop-down list, choose one of the following only (do not choose "No scanning"): "Cloud scanning" or "On device scanning".
8. Do not select the "Allow users to override blocked resources and enable access to the requested domain" check box.
9. Repeat steps 4–8 for the other platform (iOS or Android).
10. Click "Save".
11. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60948r918374_chk'
  tag severity: 'medium'
  tag gid: 'V-257264'
  tag rid: 'SV-257264r918376_rule'
  tag stig_id: 'BBCP-00-013000'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60890r918375_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
