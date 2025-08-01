control 'SV-219383' do
  title 'A managed photo app must be used to take and store work-related photos.'
  desc "The iOS Photos app is unmanaged and may sync photos with a device user's personal iCloud account. Therefore work-related photos should not be taken via the iOS camera app or stored in the Photos app. A managed photo app should be used to take and manage work-related photos.

SFR ID: NA"
  desc 'check', 'Review configuration settings to confirm a managed photos app is installed on the iOS device.

This check procedure is performed on the iPhone and iPad.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the DoD Configuration Profile from the Apple iOS/iPadOS management tool.
5. Tap "Apps".
6. Verify a photo capture and management app is listed.

If a managed photo capture and management app is not installed on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a managed photos app to take and manage work-related photos.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21108r547662_chk'
  tag severity: 'medium'
  tag gid: 'V-219383'
  tag rid: 'SV-219383r604137_rule'
  tag stig_id: 'AIOS-13-012300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21107r547663_fix'
  tag 'documentable'
  tag legacy: ['SV-106599', 'V-97495']
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
