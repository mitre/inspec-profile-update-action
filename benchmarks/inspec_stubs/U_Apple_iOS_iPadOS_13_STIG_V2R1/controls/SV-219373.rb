control 'SV-219373' do
  title 'Apple iOS/iPadOS must implement the management setting: Disable Allow MailDrop.'
  desc 'MailDrop allows users to send large attachments up to 5 GB in size via iCloud. Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Allow MailDrop" is disabled.

This validation procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow MailDrop" is not checked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Accounts".
6. Tap the "mail account".
7. Verify "Mail Drop Enabled" is set to "No".

If "Allow MailDrop" is not disabled in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad lists "Mail Drop Enabled" as "Yes", this is a finding.'
  desc 'fix', 'Configure the Apple iOS/iPadOS configuration profile to disable "Allow MailDrop".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21098r547634_chk'
  tag severity: 'medium'
  tag gid: 'V-219373'
  tag rid: 'SV-219373r604137_rule'
  tag stig_id: 'AIOS-13-011200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21097r547635_fix'
  tag 'documentable'
  tag legacy: ['SV-106579', 'V-97475']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-002314']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-17 (1)']
end
