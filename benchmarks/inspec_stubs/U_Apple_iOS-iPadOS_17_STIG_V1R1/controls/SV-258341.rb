control 'SV-258341' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: Encrypt backups/Encrypt local backup.'
  desc 'If iCloud backups are not encrypted, this could lead to the unauthorized disclosure of DOD sensitive information if non-DOD personnel are able to access that machine. Forcing the backup to be encrypted greatly mitigates the risk of compromising sensitive data. Work data iCloud backup and USB connections to computers are not authorized, but this control provides defense-in-depth for cases in which a user violates policy either intentionally or inadvertently.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Force encrypted backups" is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Encrypt local backup" is checked.

Alternatively, verify the text "<key>forceEncryptedBackup</key><true/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Encrypt backups enforced" is listed.

If "Encrypt local backup" is unchecked in the Apple iOS/iPadOS management tool, "<key>forceEncryptedBackup</key><false/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Encrypt backups enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to force encrypted backups to iCloud.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62082r927704_chk'
  tag severity: 'medium'
  tag gid: 'V-258341'
  tag rid: 'SV-258341r927706_rule'
  tag stig_id: 'AIOS-17-010700'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62006r927705_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
