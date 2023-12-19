control 'SV-250950' do
  title 'Apple iOS/iPadOS 15 must implement the management setting: Encrypt iTunes backups/Encrypt local backup.'
  desc 'When syncing an iPhone and iPad to a computer running iTunes, iTunes will prompt the user to back up the iPhone and iPad. If the performed backup is not encrypted, this could lead to the unauthorized disclosure of DoD sensitive information if non-DoD personnel are able to access that machine. By forcing the backup to be encrypted, this greatly mitigates the risk of compromising sensitive data. iTunes backup and USB connections to computers are not authorized, but this control provides defense-in-depth for cases in which a user violates policy either intentionally or inadvertently.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Force encrypted backups" is enabled in iTunes (Windows) or Finder (Mac).

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Encrypt local backup" is checked.

Alternatively, verify the text "<key>forceEncryptedBackup</key><true/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Encrypt backups enforced" is listed.

If "Encrypt local backup" is unchecked in the Apple iOS/iPadOS management tool, or "<key>forceEncryptedBackup</key><false/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Encrypt backups enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to force encrypted backups to iTunes.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54385r801939_chk'
  tag severity: 'medium'
  tag gid: 'V-250950'
  tag rid: 'SV-250950r801941_rule'
  tag stig_id: 'AIOS-15-010700'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54339r801940_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
