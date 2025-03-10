control 'SV-237262' do
  title 'Apple iOS must implement the management setting: Disable Allow MailDrop.'
  desc 'MailDrop allows users to send large attachments up to 5 GB in size via iCloud. Storing data with a non-DoD cloud provider may leave the data vulnerable to breach. Disabling non-DoD cloud services mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Allow MailDrop" is disabled.

This validation procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow MailDrop" is not checked.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Accounts".
6. Tap the mail account.
7. Verify "Mail Drop Enabled" is set to "No".

If "Allow MailDrop" is not disabled in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool lists "Mail Drop Enabled" as "Yes", this is a finding.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable "Allow MailDrop".'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40481r642336_chk'
  tag severity: 'medium'
  tag gid: 'V-237262'
  tag rid: 'SV-237262r852624_rule'
  tag stig_id: 'AIOS-12-011200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40444r642337_fix'
  tag 'documentable'
  tag legacy: ['SV-96533', 'V-81819']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-002314']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-17 (1)']
end
