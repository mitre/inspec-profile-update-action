control 'SV-254584' do
  title 'Apple iOS/iPadOS 16 must not allow backup to remote systems (managed applications data stored in iCloud).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', 'Review configuration settings to confirm "Allow managed apps to store data in iCloud" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow managed apps to store data in iCloud" is unchecked.

Alternatively, verify the text "<key>allowManagedAppsCloudSync</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Managed apps cloud sync not allowed" is listed.

If "Allow managed apps to store data in iCloud" is checked in the Apple iOS/iPadOS management tool, "<key>allowManagedAppsCloudSync</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Managed apps cloud sync not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent DoD applications from storing data in iCloud.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58195r862006_chk'
  tag severity: 'medium'
  tag gid: 'V-254584'
  tag rid: 'SV-254584r862188_rule'
  tag stig_id: 'AIOS-16-003600'
  tag gtitle: 'PP-MDF-321290'
  tag fix_id: 'F-58141r862007_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-20 (2)', 'CM-6 b', 'CM-6 (1)']
end
