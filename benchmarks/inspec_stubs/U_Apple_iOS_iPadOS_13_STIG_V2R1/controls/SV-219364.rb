control 'SV-219364' do
  title 'Apple iOS/iPadOS must not allow backup to remote systems (enterprise books).'
  desc 'Enterprise books may contain DoD-sensitive information. When Enterprise books are vulnerable to attacks on the backup systems and media when backed up. Disabling the backup capability mitigates this risk. Books which are lost, accidentally deleted, or corrupted for any reason, can be easily retrieved from the original source.

SFR ID: FMT_MOF_EXT.1.2 #40'
  desc 'check', 'Review configuration settings to confirm "Allow backup of enterprise books" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow backup of enterprise books" is unchecked.

Alternatively, verify the text "<key>allowEnterpriseBookBackup</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Backing up enterprise books not allowed" is listed.

If "Allow backup of enterprise books" is checked in the Apple iOS/iPadOS management tool, "<key>allowEnterpriseBookBackup</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Backing up enterprise books not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent backup of enterprise books that could contain DoD-sensitive information.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21089r547607_chk'
  tag severity: 'medium'
  tag gid: 'V-219364'
  tag rid: 'SV-219364r604137_rule'
  tag stig_id: 'AIOS-13-004700'
  tag gtitle: 'PP-MDF-302220'
  tag fix_id: 'F-21088r547608_fix'
  tag 'documentable'
  tag legacy: ['SV-106559', 'V-97455']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
