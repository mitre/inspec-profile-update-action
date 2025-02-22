control 'SV-93147' do
  title 'A managed photo app must be used to take and store work related photos.'
  desc "The iOS Photos app is unmanaged and may sync photo's with a device user's personal iCloud account. Therefore work related photos should not be taken via the iOS camera app or stored in the Photos app. A managed photo app should be used to take and manage work related photos.

SFR ID: NA"
  desc 'check', 'Review configuration settings to confirm a managed photos app is installed on the iOS device.

This check procedure is performed on the Apple iOS device.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the DoD Configuration Profile from the Apple iOS management tool.
5. Tap "Apps".
6. Verify a photo capture and management app is listed.

If a managed photo capture and management app is not installed on the iOS device, this is a finding.'
  desc 'fix', 'Install a managed photos app to take and manage work related photos.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-78003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78441'
  tag rid: 'SV-93147r1_rule'
  tag stig_id: 'AIOS-11-012900'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
