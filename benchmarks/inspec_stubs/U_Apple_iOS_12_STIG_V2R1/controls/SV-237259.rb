control 'SV-237259' do
  title 'Apple iOS must implement the management setting: Encrypt iTunes backups.'
  desc 'When syncing an Apple iOS device to a computer running iTunes, iTunes will prompt the user to back up the Apple iOS device. If the performed backup is not encrypted, this could lead to the unauthorized disclosure of DoD-sensitive information if non-DoD personnel are able to access that machine. By forcing the backup to be encrypted, this greatly mitigates the risk of compromising sensitive data. iTunes backup and USB connections to computers are not authorized, but this control provides defense-in-depth for cases in which a user violates policy either intentionally or inadvertently.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Force encrypted backups" is enabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Force encrypted backups" is checked.

Alternatively, verify the text "<key>forceEncryptedBackup</key><true/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Encrypted backups enforced" is listed.

If "Force encrypted backups" is unchecked in the Apple iOS management tool, or "<key>forceEncryptedBackup</key><false/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Encrypted backups enforced", this is a finding.'
  desc 'fix', 'Install a configuration profile to force encrypted backups to iTunes.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40478r642327_chk'
  tag severity: 'medium'
  tag gid: 'V-237259'
  tag rid: 'SV-237259r642329_rule'
  tag stig_id: 'AIOS-12-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40441r642328_fix'
  tag 'documentable'
  tag legacy: ['SV-96527', 'V-81813']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
