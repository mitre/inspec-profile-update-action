control 'SV-250963' do
  title 'A managed photo app must be used to take and store work-related photos.'
  desc "The iOS Photos app is unmanaged and may sync photos with a device user's personal iCloud account. Therefore, work-related photos must not be taken via the iOS camera app or stored in the Photos app. A managed photo app must be used to take and manage work-related photos.

SFR ID: NA"
  desc 'check', 'Review configuration settings to confirm a managed photos app is installed on the iOS device.

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
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54398r801978_chk'
  tag severity: 'medium'
  tag gid: 'V-250963'
  tag rid: 'SV-250963r801980_rule'
  tag stig_id: 'AIOS-15-012000'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54352r801979_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
