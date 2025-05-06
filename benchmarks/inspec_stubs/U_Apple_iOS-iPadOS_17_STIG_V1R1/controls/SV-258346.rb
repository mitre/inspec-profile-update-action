control 'SV-258346' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: Disable Allow MailDrop.'
  desc 'MailDrop allows users to send large attachments (up to 5 GB) via iCloud. Storing data with a non-DOD cloud provider may leave the data vulnerable to breach. Disabling non-DOD cloud services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Allow MailDrop" is disabled.

This validation procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow MailDrop" is not checked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Mail".
6. Tap the mail account.
7. Verify "Mail Drop Enabled" is set to "No".

If "Allow MailDrop" is not disabled in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad lists "Mail Drop Enabled" as "Yes", this is a finding.'
  desc 'fix', 'Configure the Apple iOS/iPadOS configuration profile to disable "Allow MailDrop".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62087r927719_chk'
  tag severity: 'medium'
  tag gid: 'V-258346'
  tag rid: 'SV-258346r927721_rule'
  tag stig_id: 'AIOS-17-011000'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62011r927720_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002314']
  tag nist: ['CM-6 b', 'AC-17 (1)']
end
