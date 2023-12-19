control 'SV-258318' do
  title 'Apple iOS/iPadOS 17 must [selection: wipe protected data, wipe sensitive data] upon unenrollment from MDM.'
  desc 'When a mobile device is no longer going to be managed by MDM technologies, its protected/sensitive data must be sanitized because it will no longer be protected by the MDM software, putting it at much greater risk of unauthorized access and disclosure. At least one of the two options must be selected.

SFR ID: FMT_SMF_EXT.2.1'
  desc 'check', 'Note: Not all Apple iOS/iPadOS deployments involve MDM. If the site uses an authorized alternative to MDM for distribution of configuration profiles (Apple Configurator), this check procedure is not applicable.

This check procedure is performed on the Apple iOS/iPadOS management tool or on the iOS device.

In the Apple iOS/iPadOS management tool, for each managed app, verify the app is configured to be removed when the MDM profile is removed.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Apps".
6. Tap an app and verify "App and data will be removed when device is no longer managed" is listed.

Repeat steps 5 and 6 for each managed app in the list.

If one or more managed apps are not set to be removed upon device MDM unenrollment, this is a finding.'
  desc 'fix', 'Install a configuration profile to delete all managed apps upon device unenrollment.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62059r927635_chk'
  tag severity: 'medium'
  tag gid: 'V-258318'
  tag rid: 'SV-258318r927637_rule'
  tag stig_id: 'AIOS-17-004900'
  tag gtitle: 'PP-MDF-331400'
  tag fix_id: 'F-61983r927636_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001033']
  tag nist: ['CM-6 b', 'MP-6 (3)']
end
