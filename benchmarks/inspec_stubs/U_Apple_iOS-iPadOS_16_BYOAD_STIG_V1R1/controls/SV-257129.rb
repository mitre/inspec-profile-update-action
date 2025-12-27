control 'SV-257129' do
  title 'A managed photo app must be used to take and store work-related photos.'
  desc "The iOS Photos app is unmanaged and may sync photos with a device user's personal iCloud account. Therefore, work-related photos must not be taken via the iOS camera app or stored in the Photos app. A managed photo app must be used to take and manage work-related photos.

SFR ID: NA"
  desc 'check', 'Review configuration settings to confirm a managed photos app is installed on the iOS device.

This check procedure is performed on the iPhone and iPad.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the DOD Configuration Profile from the Apple iOS/iPadOS management tool.
5. Tap "Apps".
6. Verify a photo capture and management app is listed.

If a managed photo capture and management app is not installed on the iPhone and iPad, this is a finding.'
  desc 'fix', 'Install a managed photos app to take and manage work-related photos.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60814r904285_chk'
  tag severity: 'medium'
  tag gid: 'V-257129'
  tag rid: 'SV-257129r904287_rule'
  tag stig_id: 'AIOS-16-712000'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-60755r904286_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
