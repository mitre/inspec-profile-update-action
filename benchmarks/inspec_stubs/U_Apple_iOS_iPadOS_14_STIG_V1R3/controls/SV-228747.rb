control 'SV-228747' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (enterprise books).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD-sensitive Information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', 'Review configuration settings to confirm "Allow backup of enterprise books" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow backup of enterprise books" is unchecked.

Alternatively, verify the text "<key>allowEnterpriseBookBackup</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Backing up enterprise books not allowed" is listed.

If "Allow backup of enterprise books" is checked in the Apple iOS/iPadOS management tool, "<key>allowEnterpriseBookBackup</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Backing up enterprise books not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent backup of enterprise books that could contain DoD-sensitive information.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30982r509869_chk'
  tag severity: 'medium'
  tag gid: 'V-228747'
  tag rid: 'SV-228747r561031_rule'
  tag stig_id: 'AIOS-14-004300'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-30959r509870_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
