control 'SV-228766' do
  title 'A managed photo app must be used to take and store work-related photos.'
  desc "The iOS Photos app is unmanaged and may sync photos with a device user's personal iCloud account. Therefore, work-related photos should not be taken via the iOS camera app or stored in the Photos app. A managed photo app should be used to take and manage work-related photos.

SFR ID: NA"
  desc 'check', 'Review configuration settings to confirm a managed photos app is installed on the iOS device.

Valid exception to the requirement:  If the AO has not approved a work camera app or the AO has not approved the use of the camera for work/mission activities, AND the site user agreement includes a statement that using the DoD iPhone to take work related photos is prohibited.

This check procedure is performed on the iPhone and iPad.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the DoD Configuration Profile from the Apple iOS/iPadOS management tool.
5. Tap "Apps".
6. Verify a photo capture and management app is listed.

If a managed photo capture and management app is not installed on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a managed photos app to take and manage work-related photos.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-31001r645690_chk'
  tag severity: 'medium'
  tag gid: 'V-228766'
  tag rid: 'SV-228766r561031_rule'
  tag stig_id: 'AIOS-14-010400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30978r509927_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
