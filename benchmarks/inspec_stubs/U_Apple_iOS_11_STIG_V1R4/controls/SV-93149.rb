control 'SV-93149' do
  title 'Apple iOS must not allow backup to remote systems (managed applications data stored in iCloud).'
  desc 'Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review configuration settings to confirm "Allow managed apps to store data in iCloud" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow managed apps to store data in iCloud" is unchecked.

Alternatively, verify the text "<key>allowManagedAppsCloudSync</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Managed apps cloud sync not allowed" is listed.

If "Allow managed apps to store data in iCloud" is checked in the Apple iOS management tool, "<key>allowManagedAppsCloudSync</key> <true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Managed apps cloud sync not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent DoD applications from storing data in iCloud.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-78005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78443'
  tag rid: 'SV-93149r1_rule'
  tag stig_id: 'AIOS-11-011400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
