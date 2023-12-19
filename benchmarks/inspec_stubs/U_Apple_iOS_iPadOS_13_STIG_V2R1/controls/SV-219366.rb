control 'SV-219366' do
  title 'Apple iOS/iPadOS must implement the management setting: remove managed applications upon unenrollment from MDM (including sensitive and protected data).'
  desc 'When a device is unenrolled from MDM, it is possible to relax the security policies that the MDM had implemented on the device. This may cause apps and data to be more vulnerable than prior to enrollment. Removing managed apps (and consequently the data maintained within) upon unenrollment mitigates this risk because on appropriately configured iPhone and iPads, DoD-sensitive information exists only within managed apps.

'
  desc 'check', 'Note: Not all Apple iOS/iPadOS deployments involve MDM. If the site uses an authorized alternative to MDM for distribution of configuration profiles (Apple Configurator), this check procedure is not applicable.

This check procedure is performed on the Apple iOS/iPadOS management tool or on the iOS device.

In the Apple iOS/iPadOS management tool, for each managed app, verify the app is configured to be removed when the MDM profile is removed.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Apps".
6. Tap an app and verify "App and data will be removed when device is no longer managed" is listed.

Repeat steps 5 and 6 for each managed app in the list.

If one or more managed apps are not set to be removed upon device MDM unenrollment, this is a finding.'
  desc 'fix', 'Install a configuration profile to delete all managed apps upon device unenrollment.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21091r547613_chk'
  tag severity: 'medium'
  tag gid: 'V-219366'
  tag rid: 'SV-219366r604137_rule'
  tag stig_id: 'AIOS-13-008900'
  tag gtitle: 'PP-MDF-302510'
  tag fix_id: 'F-21090r547614_fix'
  tag satisfies: ['PP-MDF-302510', 'PP-MDF-302505', 'PP-MDF-301500', 'MDF-PP-2500', 'MDF-PP-301510\n\nSFR ID: FMT_SMF_EXT.2.1', 'FMT_SMF_EXT.1.1 #47h']
  tag 'documentable'
  tag legacy: ['SV-106565', 'V-97461']
  tag cci: ['CCI-000370', 'CCI-000366', 'CCI-001199']
  tag nist: ['CM-6 (1)', 'CM-6 b', 'SC-28']
end
