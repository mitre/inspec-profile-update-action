control 'SV-91353' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Container Account blacklist.'
  desc 'Blacklisting all email accounts is required so only whitelisted accounts can be configured.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing Container Account Blacklisting. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Account blacklist" setting in the "Container Accounts" rule. 
2. Verify the setting is configured to all email domains not approved by DoD.

Note: All email domains are specified by the wildcard string ".*"

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox Container.
2. Open "Settings".
3. Select "Accounts".
4. Select "Add account".
5. Select "Email" (and repeat for Microsoft Exchange ActiveSync) and attempt to add an email account with a non-approved domain.
6. Verify the email account cannot be added.

If the MDM console "Account blacklist" is not set to all email domains not approved by DoD or on the Samsung Android 7 with Knox device, the user is able to successfully configure the non-DoD-approved email account, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce Container Account Blacklisting.

On the MDM console, add all email domains not approved by DoD to the "Account blacklist" setting in the "Container Accounts" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76657'
  tag rid: 'SV-91353r1_rule'
  tag stig_id: 'KNOX-07-914400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
