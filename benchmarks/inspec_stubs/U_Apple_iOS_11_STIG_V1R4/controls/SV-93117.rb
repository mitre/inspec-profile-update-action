control 'SV-93117' do
  title 'Apple iOS must not allow backup to remote systems (enterprise books).'
  desc 'Enterprise books may contain DoD-sensitive information. When enterprise books are backed up, they are vulnerable to attacks on the backup systems and media. Disabling the backup capability mitigates this risk. If such books are lost, accidentally deleted, or corrupted for any reason, they can be easily retrieved from the original source.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review configuration settings to confirm "Allow backup of enterprise books" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow backup of enterprise books" is unchecked.

Alternatively, verify the text "<key>allowEnterpriseBookBackup</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Backing up enterprise books not allowed" is listed.

If "Allow backup of enterprise books" is checked in the Apple iOS management tool, "<key>allowEnterpriseBookBackup</key> <true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Backing up enterprise books not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent backup of enterprise books that could contain DoD-sensitive information.'
  impact 0.3
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77973r1_chk'
  tag severity: 'low'
  tag gid: 'V-78411'
  tag rid: 'SV-93117r1_rule'
  tag stig_id: 'AIOS-11-011200'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-85143r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002338']
  tag nist: ['AC-20 (3)']
end
