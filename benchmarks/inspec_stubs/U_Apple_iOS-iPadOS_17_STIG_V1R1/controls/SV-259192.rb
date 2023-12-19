control 'SV-259192' do
  title 'Apple iOS/iPadOS 17 must not allow backup to remote systems (enterprise books).'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', 'Review configuration settings to confirm "Allow backup of enterprise books" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow backup of enterprise books" is unchecked.

Alternatively, verify the text "<key>allowEnterpriseBookBackup</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Backing up enterprise books not allowed" is listed.

If "Allow backup of enterprise books" is checked in the Apple iOS/iPadOS management tool, "<key>allowEnterpriseBookBackup</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Backing up enterprise books not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent backup of enterprise books that could contain DOD sensitive information.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62932r935544_chk'
  tag severity: 'medium'
  tag gid: 'V-259192'
  tag rid: 'SV-259192r935546_rule'
  tag stig_id: 'AIOS-17-003700'
  tag gtitle: 'PP-MDF-333250'
  tag fix_id: 'F-62841r935545_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
