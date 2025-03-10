control 'SV-94865' do
  title 'Samsung Android 8 with Knox must implement the management setting: Account whitelist.'
  desc 'Whitelisting of authorized email accounts (POP3, IMAP, EAS) prevents a user from configuring a personal email account that could be used to forward sensitive DoD data to unauthorized recipients.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing Account Whitelisting. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Account whitelist" setting in the "Android Accounts" rule. 
2. Verify the whitelist only contains DoD-approved email domains (for example, mail.mil).
Note: Proper configuration of Account blacklist is required for this configuration to function correctly.

On the Samsung Android 8 with Knox device, do the following:
1. Open device settings.
2. Select "Accounts".
3. Select "Accounts".
4. Select "Add account".
5. Select "Email" (and repeat for Microsoft Exchange ActiveSync) and attempt to add an email account with a DoD-approved domain.
6. Verify the email account can be added.
7. Attempt to add an email account with a domain not approved by DoD.
8. Verify that the email account cannot be added.

If the MDM console "Account whitelist" is not set to contain DoD-approved email domains, or on the Samsung Android 8 with Knox device, the user is able to successfully configure the email account with a domain not approved by DoD, or the user is not able to install the DoD-approved email account, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce Account Whitelisting.

On the MDM console, add all DoD-approved email domains to the "Account whitelist" setting in the "Android Accounts" rule.

Note: Recommended to add .*@mail.mil.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80161'
  tag rid: 'SV-94865r1_rule'
  tag stig_id: 'KNOX-08-000100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-86967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
