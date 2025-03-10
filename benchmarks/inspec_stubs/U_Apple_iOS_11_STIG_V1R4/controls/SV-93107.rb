control 'SV-93107' do
  title 'Apple iOS must implement the management setting: remove managed applications upon unenrollment from MDM (including sensitive and protected data).'
  desc 'When a device is unenrolled from MDM, it is possible to relax the security policies that the MDM had implemented on the device. This may cause apps and data to be more vulnerable than they were prior to enrollment. Removing managed apps (and consequently the data they maintain) upon unenrollment mitigates this risk because on appropriately configured Apple iOS devices, DoD-sensitive information exists only within managed apps.

'
  desc 'check', 'Note: The procedure below is exactly the same for requirement AIOS-11-008700. This procedure needs to be performed only once.

Note: Not all Apple iOS deployments involve MDM. If the site uses an authorized alternative to MDM for distribution of configuration profiles (Apple Configurator), this check procedure is not applicable.

This check procedure is performed on the Apple iOS management tool or on the iOS device.

In the Apple iOS management tool, for each managed app, verify the app is configured to be removed when the MDM profile is removed.

On the Apple iOS device:
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "App".
6. Tap an app and verify "App and data will be removed when device is no longer managed" is listed.

Repeat steps 5 and 6 for each managed app in the list.

If one or more managed apps are not set to be removed upon device MDM unenrollment, this is a finding.'
  desc 'fix', 'Install a configuration profile to delete all managed apps upon device unenrollment.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78401'
  tag rid: 'SV-93107r1_rule'
  tag stig_id: 'AIOS-11-007200'
  tag gtitle: 'PP-MDF-301500'
  tag fix_id: 'F-85133r1_fix'
  tag satisfies: ['PP-MDF-301500', 'PP-MDF-301510', 'PP-MDF-302500', 'PP-MDF-302510', 'PP-MDF-991000\n\nSFR ID: FMT_SMF_EXT.1.1 #44', '#47', 'FMT_SMF_EXT.2.1']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001028']
  tag nist: ['CM-6 b', 'MP-6 a']
end
